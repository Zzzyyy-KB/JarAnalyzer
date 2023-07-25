package zju.cst.aces;

import org.apache.tools.ant.DirectoryScanner;
import zju.cst.aces.dependencycheck.Engine;

import zju.cst.aces.dependencycheck.exception.ExceptionCollection;
import zju.cst.aces.dependencycheck.exception.ReportException;
import zju.cst.aces.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class demo {

    private final Settings settings;
    /**
     * System specific new line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator", "\n");
    public static void main(String[] args) {
        System.out.println("输入jar包所在目录");
        final demo demo = new demo();
//:\:\java\JavaCallGraph\target\JavaCallgraph-1.0-SNAPSHOT-jar-with-dependencies.jar
        try{  String[] scanfiles = new String[]{"D:\\java\\cg.jar"};
            String[] oF=new String[]{"html"};
            String[] excl = new String[]{""};
            demo.runScan("D:\\1postgraduate", oF, "", scanfiles
                    , excl, 0, 11,"./cgconfig.json");}
        catch( ExceptionCollection | ReportException ex) {
            System.out.println(ex.getMessage());
            System.out.println("database exception");
        }
    }

    public demo() {
        settings = new Settings();
        Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, settings);
    }

    /**
     * Builds the App object; this method is used for testing.
     *
     * @param settings the configured settings
     */

    protected demo(Settings settings) {
        this.settings = settings;
        Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, settings);
    }


    /**
     * Takes a path and resolves it to be a canonical &amp; absolute path. The
     * caveats are that this method will take an Ant style file selector path
     * (../someDir/**\/*.jar) and convert it to an absolute/canonical path (at
     * least to the left of the first * or ?).
     *
     * @param path the path to canonicalize
     * @return the canonical path
     */
    protected String ensureCanonicalPath(String path) {
        final String basePath;
        String wildCards = null;
        final String file = path.replace('\\', '/');
        if (file.contains("*") || file.contains("?")) {

            int pos = getLastFileSeparator(file);
            if (pos < 0) {
                return file;
            }
            pos += 1;
            basePath = file.substring(0, pos);
            wildCards = file.substring(pos);
        } else {
            basePath = file;
        }

        File f = new File(basePath);
        try {
            f = f.getCanonicalFile();
            if (wildCards != null) {
                f = new File(f, wildCards);
            }
        } catch (IOException ex) {
            System.out.println("Invalid path " + path + " was provided.");
        }
        return f.getAbsolutePath().replace('\\', '/');
    }


    /**
     * Returns the position of the last file separator.
     *
     * @param file a file path
     * @return the position of the last file separator
     */
    @SuppressWarnings("ManualMinMaxCalculation")
    private int getLastFileSeparator(String file) {
        if (file.contains("*") || file.contains("?")) {
            int p1 = file.indexOf('*');
            int p2 = file.indexOf('?');
            p1 = p1 > 0 ? p1 : file.length();
            p2 = p2 > 0 ? p2 : file.length();
            int pos = p1 < p2 ? p1 : p2;
            pos = file.lastIndexOf('/', pos);
            return pos;
        } else {
            return file.lastIndexOf('/');
        }
    }


    private List<String> getPaths(String[] files) {
        final List<String> antStylePaths = new ArrayList<>();
        for (String file : files) {
            final String antPath = ensureCanonicalPath(file);
            antStylePaths.add(antPath);
        }
        return antStylePaths;
    }


    private Set<File> scanAntStylePaths(List<String> antStylePaths, int symLinkDepth, String[] excludes) {
        final Set<File> paths = new TreeSet<>();
        for (String file : antStylePaths) {
            System.out.println("Scanning" + file);
            final DirectoryScanner scanner = new DirectoryScanner();
            String include = file.replace('\\', '/');
            final File baseDir;
            final int pos = getLastFileSeparator(include);
            final String tmpBase = include.substring(0, pos);
            final String tmpInclude = include.substring(pos + 1);
            if (tmpInclude.indexOf('*') >= 0 || tmpInclude.indexOf('?') >= 0
                    || new File(include).isFile()) {
                baseDir = new File(tmpBase);
                include = tmpInclude;
            } else {
                baseDir = new File(tmpBase, tmpInclude);
                include = "**/*";
            }
            System.out.println("BaseDir: " + baseDir);
            System.out.println("Include: " + include);
            scanner.setBasedir(baseDir);
            final String[] includes = {include};
            scanner.setIncludes(includes);
            scanner.setMaxLevelsOfSymlinks(symLinkDepth);
            if (symLinkDepth <= 0) {
                scanner.setFollowSymlinks(false);
            }
            if (excludes != null && excludes.length > 0) {
                for (String e : excludes) {
                    System.out.println("Exclude: " + e);
                }
                scanner.addExcludes(excludes);
            }
            scanner.scan();
            if (scanner.getIncludedFilesCount() > 0) {
                for (String s : scanner.getIncludedFiles()) {
                    final File f = new File(baseDir, s);
                    System.out.println("Found file" + f);
                    paths.add(f);
                }
            }
        }
        return paths;
    }


    private int runScan(String reportDirectory, String[] outputFormats, String applicationName, String files[],
                        String excludes[], int symLinkDepth, float cvssFailScore,String markfile)throws
            ExceptionCollection, ReportException  {
        Engine engine = null;
        try {
            final List<String> antStylePaths = getPaths(files);
            final Set<File> paths = scanAntStylePaths(antStylePaths, symLinkDepth, excludes);

            engine = new Engine(settings);
            engine.scan(paths);

            ExceptionCollection exCol = null;
            try {
                engine.analyzeDependencies(markfile);
            } catch (ExceptionCollection ex) {
                if (ex.isFatal()) {
                    throw ex;
                }
                exCol = ex;
            }

    }catch (ExceptionCollection e){
            e.printStackTrace();
        }
        return symLinkDepth;
    }

}
