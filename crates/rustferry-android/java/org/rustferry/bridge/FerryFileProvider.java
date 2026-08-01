package org.rustferry.bridge;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/** Read-only content provider for files in application-owned directories. */
public final class FerryFileProvider extends ContentProvider {
    static Uri uriFor(Context context, String source) throws IOException {
        File file = new File(source).getCanonicalFile();
        Root root = findRoot(context, file);
        if (root == null) {
            throw new SecurityException("shared files must be inside an application-owned directory");
        }
        String rootPath = root.directory.getCanonicalPath() + File.separator;
        String filePath = file.getCanonicalPath();
        if (!filePath.startsWith(rootPath)) {
            throw new SecurityException("shared file escaped its application-owned directory");
        }
        String relative = filePath.substring(rootPath.length());
        return new Uri.Builder()
                .scheme("content")
                .authority(context.getPackageName() + ".ferry-files")
                .appendPath(root.name)
                .appendPath(relative)
                .build();
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public String getType(Uri uri) {
        File file = resolve(uri);
        String extension = MimeTypeMap.getFileExtensionFromUrl(file.getName());
        String type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
        return type == null ? "application/octet-stream" : type;
    }

    @Override
    public Cursor query(
            Uri uri,
            String[] projection,
            String selection,
            String[] selectionArgs,
            String sortOrder) {
        File file = resolve(uri);
        String[] requested = projection == null
                ? new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}
                : projection;
        MatrixCursor cursor = new MatrixCursor(requested, 1);
        Object[] values = new Object[requested.length];
        for (int index = 0; index < requested.length; index++) {
            if (OpenableColumns.DISPLAY_NAME.equals(requested[index])) {
                values[index] = file.getName();
            } else if (OpenableColumns.SIZE.equals(requested[index])) {
                values[index] = file.length();
            }
        }
        cursor.addRow(values);
        return cursor;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) {
            throw new SecurityException("RustFerry shared files are read-only");
        }
        File file = resolve(uri);
        if (!file.isFile()) {
            throw new FileNotFoundException("shared file does not exist");
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("read-only provider");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("read-only provider");
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("read-only provider");
    }

    private File resolve(Uri uri) {
        Context context = getContext();
        if (context == null
                || !"content".equals(uri.getScheme())
                || !(context.getPackageName() + ".ferry-files").equals(uri.getAuthority())) {
            throw new SecurityException("invalid RustFerry file URI");
        }
        java.util.List<String> segments = uri.getPathSegments();
        if (segments.size() != 2) {
            throw new SecurityException("invalid RustFerry file path");
        }
        Root root = rootNamed(context, segments.get(0));
        if (root == null) {
            throw new SecurityException("unknown RustFerry file root");
        }
        try {
            File candidate = new File(root.directory, segments.get(1)).getCanonicalFile();
            String rootPath = root.directory.getCanonicalPath() + File.separator;
            if (!candidate.getCanonicalPath().startsWith(rootPath)) {
                throw new SecurityException("RustFerry file path escaped its root");
            }
            return candidate;
        } catch (IOException error) {
            throw new SecurityException("RustFerry file path is invalid", error);
        }
    }

    private static Root findRoot(Context context, File file) throws IOException {
        for (Root root : roots(context)) {
            if (root.directory == null) continue;
            String prefix = root.directory.getCanonicalPath() + File.separator;
            if (file.getCanonicalPath().startsWith(prefix)) {
                return root;
            }
        }
        return null;
    }

    private static Root rootNamed(Context context, String name) {
        for (Root root : roots(context)) {
            if (root.directory != null && root.name.equals(name)) {
                return root;
            }
        }
        return null;
    }

    private static Root[] roots(Context context) {
        return new Root[] {
                new Root("files", context.getFilesDir()),
                new Root("cache", context.getCacheDir()),
                new Root("external-files", context.getExternalFilesDir(null)),
                new Root("external-cache", context.getExternalCacheDir())
        };
    }

    private static final class Root {
        final String name;
        final File directory;

        Root(String name, File directory) {
            this.name = name;
            this.directory = directory;
        }
    }
}
