package io.github.authme.fabric.util;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * File helpers for AuthMe data which can contain database credentials or account state.
 *
 * <p>POSIX permissions are applied when available. Windows ACLs are reduced to an allow entry
 * for the current file owner when an ACL view is available. All operations reject symbolic links
 * so an accidentally redirected config or backup path cannot overwrite an unrelated file.</p>
 */
public final class SecureFileAccess {

    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY = Set.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> PRIVATE_FILE = Set.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private SecureFileAccess() { }

    public static void ensurePrivateDirectory(Path directory) throws IOException {
        if (directory == null) throw new IOException("Directory path is missing");
        if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)
            && Files.isSymbolicLink(directory)) {
            throw new IOException("Refusing to use symbolic-link directory: " + directory);
        }
        createDirectoriesPrivately(directory);
        harden(directory);
    }

    /** Tightens an existing regular file or directory without following a symbolic link. */
    public static void harden(Path path) throws IOException {
        if (path == null || !Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isSymbolicLink(path)) {
            throw new IOException("Refusing to use symbolic-link file: " + path);
        }
        boolean directory = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS);
        if (!directory && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Refusing to use non-regular sensitive file: " + path);
        }
        try {
            Files.setPosixFilePermissions(path, directory ? PRIVATE_DIRECTORY : PRIVATE_FILE);
        } catch (UnsupportedOperationException ignored) {
            // Windows and other non-POSIX file systems use the ACL path below.
        }
        hardenAcl(path, directory);
    }

    /** Creates a file without following an existing symbolic link, then restricts its access. */
    public static OutputStream createNewPrivateFile(Path file) throws IOException {
        if (file == null) throw new IOException("File path is missing");
        Path parent = file.toAbsolutePath().normalize().getParent();
        if (parent != null) ensurePrivateDirectory(parent);
        if (Files.isSymbolicLink(file)) {
            throw new IOException("Refusing to overwrite symbolic-link file: " + file);
        }
        SeekableByteChannel channel;
        try {
            channel = Files.newByteChannel(file,
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PRIVATE_FILE));
        } catch (UnsupportedOperationException unsupported) {
            channel = Files.newByteChannel(file,
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE));
        }
        OutputStream output = Channels.newOutputStream(channel);
        try {
            harden(file);
            return output;
        } catch (IOException e) {
            try { output.close(); } catch (IOException ignored) { }
            Files.deleteIfExists(file);
            throw e;
        }
    }

    /** Creates a restricted temporary file in a restricted directory for an atomic replacement. */
    public static Path createPrivateTempFile(Path directory, String prefix, String suffix)
        throws IOException {
        if (directory == null) throw new IOException("Temporary-file directory is missing");
        if (Files.isSymbolicLink(directory)) {
            throw new IOException("Refusing to use symbolic-link temporary-file directory: " + directory);
        }
        createDirectoriesPrivately(directory);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Temporary-file parent is not a directory: " + directory);
        }
        harden(directory);
        Path temporary;
        try {
            temporary = Files.createTempFile(directory, prefix, suffix,
                PosixFilePermissions.asFileAttribute(PRIVATE_FILE));
        } catch (UnsupportedOperationException unsupported) {
            temporary = Files.createTempFile(directory, prefix, suffix);
        }
        try {
            harden(temporary);
            return temporary;
        } catch (IOException e) {
            Files.deleteIfExists(temporary);
            throw e;
        }
    }

    /** Replaces a regular target with a restricted temporary file where the file system permits it. */
    public static void replace(Path temporary, Path target) throws IOException {
        if (temporary == null || target == null) throw new IOException("Replacement path is missing");
        if (Files.isSymbolicLink(target)) {
            throw new IOException("Refusing to replace symbolic-link file: " + target);
        }
        harden(temporary);
        try {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
        harden(target);
    }

    /** Applies owner-only attributes at creation time where the file-system provider supports it. */
    private static void createDirectoriesPrivately(Path directory) throws IOException {
        try {
            Files.createDirectories(directory,
                PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY));
        } catch (UnsupportedOperationException unsupported) {
            Files.createDirectories(directory);
        }
    }

    private static void hardenAcl(Path path, boolean directory) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class,
            LinkOption.NOFOLLOW_LINKS);
        if (view == null) return;
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        Set<AclEntryPermission> permissions = directory
            ? EnumSet.of(AclEntryPermission.LIST_DIRECTORY, AclEntryPermission.ADD_FILE,
                AclEntryPermission.ADD_SUBDIRECTORY, AclEntryPermission.READ_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.DELETE,
                AclEntryPermission.DELETE_CHILD, AclEntryPermission.READ_ACL,
                AclEntryPermission.WRITE_ACL, AclEntryPermission.EXECUTE,
                AclEntryPermission.SYNCHRONIZE)
            : EnumSet.of(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
                AclEntryPermission.APPEND_DATA, AclEntryPermission.READ_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.DELETE,
                AclEntryPermission.READ_ACL, AclEntryPermission.WRITE_ACL,
                AclEntryPermission.SYNCHRONIZE);
        AclEntry entry = AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(owner)
            .setPermissions(permissions)
            .build();
        view.setAcl(List.of(entry));
    }
}
