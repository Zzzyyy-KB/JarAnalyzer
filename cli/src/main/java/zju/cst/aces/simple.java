//package zju.cst.aces.dependencycheck;
//
//import org.apache.tools.ant.DirectoryScanner;
//import zju.cst.aces.dependencycheck.data.nvdcve.DatabaseException;
//import zju.cst.aces.dependencycheck.dependency.Dependency;
//import zju.cst.aces.dependencycheck.dependency.Vulnerability;
//import zju.cst.aces.dependencycheck.exception.ExceptionCollection;
//import zju.cst.aces.dependencycheck.exception.ReportException;
//import zju.cst.aces.dependencycheck.utils.Settings;
//import zju.cst.aces.dependencycheck.utils.SeverityUtil;
//
//import java.io.File;
//import java.io.IOException;
//import java.util.*;
//
//public class simple {
//
//    private final Settings settings;
//    /**
//     * System specific new line character.
//     */
//    private static final String NEW_LINE = System.getProperty("line.separator", "\n");
//
//    public simple() {
//        settings = new Settings();
//        Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, settings);
//    }
//
//    public static void main(String[] args) {
//        System.out.println("输入jar包所在目录");
//        final simple simple = new simple();
//
//        try{  String[] scanfiles = new String[]{"D:\\1postgraduate\\see包\\OMC\\bizframe-cloud-server-2.0.85.2\\bizframe\\bizframe"};
//            String[] oF=new String[]{"json"};
//            String[] excl = new String[]{""};
//            simple.runScan("D:\\1postgraduate", oF, "", scanfiles
//                    , excl, 0, 11);}
//        catch(DatabaseException | ExceptionCollection | ReportException ex) {
//            System.out.println(ex.getMessage());
//            System.out.println("database exception");
//        }
//    }
//
//
//
//    /**
//     * Builds the App object; this method is used for testing.
//     *
//     * @param settings the configured settings
//     */
//
//    protected simple(Settings settings) {
//        this.settings = settings;
//        Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, settings);
//    }
//
//
//    /**
//     * Takes a path and resolves it to be a canonical &amp; absolute path. The
//     * caveats are that this method will take an Ant style file selector path
//     * (../someDir/**\/*.jar) and convert it to an absolute/canonical path (at
//     * least to the left of the first * or ?).
//     *
//     * @param path the path to canonicalize
//     * @return the canonical path
//     */
//    protected String ensureCanonicalPath(String path) {
//        final String basePath;
//        String wildCards = null;
//        final String file = path.replace('\\', '/');
//        if (file.contains("*") || file.contains("?")) {
//
//            int pos = getLastFileSeparator(file);
//            if (pos < 0) {
//                return file;
//            }
//            pos += 1;
//            basePath = file.substring(0, pos);
//            wildCards = file.substring(pos);
//        } else {
//            basePath = file;
//        }
//
//        File f = new File(basePath);
//        try {
//            f = f.getCanonicalFile();
//            if (wildCards != null) {
//                f = new File(f, wildCards);
//            }
//        } catch (IOException ex) {
//            System.out.println("Invalid path " + path + " was provided.");
//        }
//        return f.getAbsolutePath().replace('\\', '/');
//    }
//
//
//    /**
//     * Returns the position of the last file separator.
//     *
//     * @param file a file path
//     * @return the position of the last file separator
//     */
//    @SuppressWarnings("ManualMinMaxCalculation")
//    private int getLastFileSeparator(String file) {
//        if (file.contains("*") || file.contains("?")) {
//            int p1 = file.indexOf('*');
//            int p2 = file.indexOf('?');
//            p1 = p1 > 0 ? p1 : file.length();
//            p2 = p2 > 0 ? p2 : file.length();
//            int pos = p1 < p2 ? p1 : p2;
//            pos = file.lastIndexOf('/', pos);
//            return pos;
//        } else {
//            return file.lastIndexOf('/');
//        }
//    }
//
//
//    private List<String> getPaths(String[] files) {
//        final List<String> antStylePaths = new ArrayList<>();
//        for (String file : files) {
//            final String antPath = ensureCanonicalPath(file);
//            antStylePaths.add(antPath);
//        }
//        return antStylePaths;
//    }
//
//
//    private Set<File> scanAntStylePaths(List<String> antStylePaths, int symLinkDepth, String[] excludes) {
//        final Set<File> paths = new TreeSet<>();
//        for (String file : antStylePaths) {
//            System.out.println("Scanning" + file);
//            final DirectoryScanner scanner = new DirectoryScanner();
//            String include = file.replace('\\', '/');
//            final File baseDir;
//            final int pos = getLastFileSeparator(include);
//            final String tmpBase = include.substring(0, pos);
//            final String tmpInclude = include.substring(pos + 1);
//            if (tmpInclude.indexOf('*') >= 0 || tmpInclude.indexOf('?') >= 0
//                    || new File(include).isFile()) {
//                baseDir = new File(tmpBase);
//                include = tmpInclude;
//            } else {
//                baseDir = new File(tmpBase, tmpInclude);
//                include = "**/*";
//            }
//            System.out.println("BaseDir: " + baseDir);
//            System.out.println("Include: " + include);
//            scanner.setBasedir(baseDir);
//            final String[] includes = {include};
//            scanner.setIncludes(includes);
//            scanner.setMaxLevelsOfSymlinks(symLinkDepth);
//            if (symLinkDepth <= 0) {
//                scanner.setFollowSymlinks(false);
//            }
//            if (excludes != null && excludes.length > 0) {
//                for (String e : excludes) {
//                    System.out.println("Exclude: " + e);
//                }
//                scanner.addExcludes(excludes);
//            }
//            scanner.scan();
//            if (scanner.getIncludedFilesCount() > 0) {
//                for (String s : scanner.getIncludedFiles()) {
//                    final File f = new File(baseDir, s);
//                    System.out.println("Found file" + f);
//                    paths.add(f);
//                }
//            }
//        }
//        return paths;
//    }
//
//
//    private int runScan(String reportDirectory, String[] outputFormats, String applicationName, String files[],
//                        String excludes[], int symLinkDepth, float cvssFailScore)throws DatabaseException,
//            ExceptionCollection, ReportException  {
//        Engine engine = null;
//        try {
//            final List<String> antStylePaths = getPaths(files);
//            final Set<File> paths = scanAntStylePaths(antStylePaths, symLinkDepth, excludes);
//
//            engine = new Engine(settings);
//            engine.scan(paths);
//
//            ExceptionCollection exCol = null;
//            try {
//                engine.analyzeDependencies();
//            } catch (ExceptionCollection ex) {
//                if (ex.isFatal()) {
//                    throw ex;
//                }
//                exCol = ex;
//            }
//
//            try {
//                for (String outputFormat : outputFormats) {
//                    engine.writeReports(applicationName, new File(reportDirectory), outputFormat, exCol);
//                }
//            } catch (ReportException ex) {
//                if (exCol != null) {
//                    exCol.addException(ex);
//                    throw exCol;
//                } else {
//                    throw ex;
//                }
//            }
//            if (exCol != null && !exCol.getExceptions().isEmpty()) {
//                throw exCol;
//            }
//            return determineReturnCode(engine, cvssFailScore);
//        } finally {
//            if (engine != null) {
//                engine.close();
//            }
//        }
//    }
//    /**
//     * Determines the return code based on if one of the dependencies scanned
//     * has a vulnerability with a CVSS score above the cvssFailScore.
//     *
//     * @param engine the engine used during analysis
//     * @param cvssFailScore the max allowed CVSS score
//     * @return returns <code>1</code> if a severe enough vulnerability is
//     * identified; otherwise <code>0</code>
//     */
//    private int determineReturnCode(Engine engine, float cvssFailScore) {
//        int retCode = 0;
//        //Set the exit code based on whether we found a high enough vulnerability
//        final StringBuilder ids = new StringBuilder();
//        for (Dependency d : engine.getDependencies()) {
//            boolean addName = true;
//            for (Vulnerability v : d.getVulnerabilities()) {
//                final float cvssV2 = v.getCvssV2() != null ? v.getCvssV2().getScore() : -1;
//                final float cvssV3 = v.getCvssV3() != null ? v.getCvssV3().getBaseScore() : -1;
//                final float unscoredCvss = v.getUnscoredSeverity() != null ? SeverityUtil.estimateCvssV2(v.getUnscoredSeverity()) : -1;
//
//                if (cvssV2 >= cvssFailScore
//                        || cvssV3 >= cvssFailScore
//                        || unscoredCvss >= cvssFailScore
//                        //safety net to fail on any if for some reason the above misses on 0
//                        || (cvssFailScore <= 0.0f)) {
//                    float score = 0.0f;
//                    if (cvssV3 >= 0.0f) {
//                        score = cvssV3;
//                    } else if (cvssV2 >= 0.0f) {
//                        score = cvssV2;
//                    } else if (unscoredCvss >= 0.0f) {
//                        score = unscoredCvss;
//                    }
//                    if (addName) {
//                        addName = false;
//                        ids.append(NEW_LINE).append(d.getFileName()).append(": ");
//                        ids.append(v.getName()).append('(').append(score).append(')');
//                    } else {
//                        ids.append(", ").append(v.getName()).append('(').append(score).append(')');
//                    }
//                }
//            }
//        }
//        if (ids.length() > 0) {
//            System.out.println(
//                    String.format("%n%nOne or more dependencies were identified with vulnerabilities that have a CVSS score greater than or "
//                            + "equal to '%.1f': %n%s%n%nSee the dependency-check report for more details.%n%n", cvssFailScore, ids)
//            );
//
//            retCode = 1;
//        }
//
//        return retCode;
//    }
//
//}
