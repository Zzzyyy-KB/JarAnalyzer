/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package zju.cst.aces.dependencycheck;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.jcs.JCS;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import zju.cst.aces.dependencycheck.analyzer.*;
import zju.cst.aces.dependencycheck.dependency.Dependency;
import zju.cst.aces.dependencycheck.exception.ExceptionCollection;
import zju.cst.aces.dependencycheck.exception.InitializationException;
import zju.cst.aces.dependencycheck.exception.ReportException;
import zju.cst.aces.dependencycheck.reporting.ReportGenerator;
import zju.cst.aces.dependencycheck.utils.Settings;
import zju.cst.aces.dependencycheck.xml.suppression.SuppressionRules;

import javax.annotation.concurrent.NotThreadSafe;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import static zju.cst.aces.dependencycheck.analyzer.AnalysisPhase.*;
import static zju.cst.aces.dependencycheck.analyzer.JarAnalyzer.formatJson;

/**
 * Scans files, directories, etc. for Dependencies. Analyzers are loaded and
 * used to process the files found by the scan, if a file is encountered and an
 * Analyzer is associated with the file type then the file is turned into a
 * dependency.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class Engine implements FileFilter, AutoCloseable {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Engine.class);
    /**
     * The list of dependencies.
     */
    private  final List<Dependency> dependencies = Collections.synchronizedList(new ArrayList<>());
    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private final Map<AnalysisPhase, List<Analyzer>> analyzers = new EnumMap<>(AnalysisPhase.class);
    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private final Set<FileTypeAnalyzer> fileTypeAnalyzers = new HashSet<>();
    /**
     * The engine execution mode indicating it will either collect evidence or
     * process evidence or both.
     */
    private final Mode mode;
    /**
     * The ClassLoader to use when dynamically loading Analyzer and Update
     * services.
     */
    private final ClassLoader serviceClassLoader;
    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * The external view of the dependency list.
     */
    private Dependency[] dependenciesExternalView = null;
    /**
     * A reference to the database.
     */
    /**
     * Used to store the value of
     * System.getProperty("javax.xml.accessExternalSchema") - ODC may change the
     * value of this system property at runtime. We store the value to reset the
     * property to its original value.
     */
    private final String accessExternalSchema;

    private  String MARKFILE;

    /**
     * Creates a new {@link Mode#STANDALONE} Engine.
     *
     * @param settings reference to the configured settings
     */
    public Engine(@NotNull final Settings settings) {
        this(Mode.STANDALONE, settings);
    }

    /**
     * Creates a new Engine.
     *
     * @param mode the mode of operation
     * @param settings reference to the configured settings
     */
    public Engine(@NotNull final Mode mode, @NotNull final Settings settings) {
        this(Thread.currentThread().getContextClassLoader(), mode, settings);
    }

    /**
     * Creates a new {@link Mode#STANDALONE} Engine.
     *
     * @param serviceClassLoader a reference the class loader being used
     * @param settings reference to the configured settings
     */
    public Engine(@NotNull final ClassLoader serviceClassLoader, @NotNull final Settings settings) {
        this(serviceClassLoader, Mode.STANDALONE, settings);
    }

    /**
     * Creates a new Engine.
     *
     * @param serviceClassLoader a reference the class loader being used
     * @param mode the mode of the engine
     * @param settings reference to the configured settings
     */
    public Engine(@NotNull final ClassLoader serviceClassLoader, @NotNull final Mode mode, @NotNull final Settings settings) {
        this.settings = settings;
        this.serviceClassLoader = serviceClassLoader;
        this.mode = mode;
        this.accessExternalSchema = System.getProperty("javax.xml.accessExternalSchema");
        initializeEngine();
    }


    protected final void initializeEngine() {
        loadAnalyzers();
    }

    /**
     * Properly cleans up resources allocated during analysis.
     */
    @Override
    public void close() {

        if (accessExternalSchema != null) {
            System.setProperty("javax.xml.accessExternalSchema", accessExternalSchema);
        } else {
            System.clearProperty("javax.xml.accessExternalSchema");
        }
        JCS.shutdown();
    }

    /**
     * Loads the analyzers specified in the configuration file (or system
     * properties).
     */
    private void loadAnalyzers() {
        if (!analyzers.isEmpty()) {
            return;
        }
        mode.getPhases().forEach((phase) -> analyzers.put(phase, new ArrayList<>()));
        final AnalyzerService service = new AnalyzerService(serviceClassLoader, settings);
        final List<Analyzer> iterator = service.getAnalyzers(mode.getPhases());
        iterator.forEach((a) -> {
            a.initialize(this.settings);
            analyzers.get(a.getAnalysisPhase()).add(a);
            if (a instanceof FileTypeAnalyzer) {
                this.fileTypeAnalyzers.add((FileTypeAnalyzer) a);
            }
        });
    }

    /**
     * Get the List of the analyzers for a specific phase of analysis.
     *
     * @param phase the phase to get the configured analyzers.
     * @return the analyzers loaded
     */
    public List<Analyzer> getAnalyzers(AnalysisPhase phase) {
        return analyzers.get(phase);
    }

    /**
     * Adds a dependency.
     *
     * @param dependency the dependency to add
     */
    public synchronized void addDependency(Dependency dependency) {
        dependencies.add(dependency);
        dependenciesExternalView = null;
    }

    /**
     * Sorts the dependency list.
     */
    public synchronized void sortDependencies() {
        //TODO - is this actually necassary????
//        Collections.sort(dependencies);
//        dependenciesExternalView = null;
    }

    /**
     * Removes the dependency.
     *
     * @param dependency the dependency to remove.
     */
    public synchronized void removeDependency(@NotNull final Dependency dependency) {
        dependencies.remove(dependency);
        dependenciesExternalView = null;
    }

    /**
     * Returns a copy of the dependencies as an array.
     *
     * @return the dependencies identified
     */
    @SuppressFBWarnings(justification = "This is the intended external view of the dependencies", value = {"EI_EXPOSE_REP"})
    public synchronized Dependency[] getDependencies() {
        if (dependenciesExternalView == null) {
            dependenciesExternalView = dependencies.toArray(new Dependency[0]);
        }
        return dependenciesExternalView;
    }

    /**
     * Sets the dependencies.
     *
     * @param dependencies the dependencies
     */
    public synchronized void setDependencies(@NotNull final List<Dependency> dependencies) {
        this.dependencies.clear();
        this.dependencies.addAll(dependencies);
        dependenciesExternalView = null;
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param paths an array of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(@NotNull final String[] paths) {
        return scan(paths, null);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param paths an array of paths to files or directories to be analyzed
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    public List<Dependency> scan(@NotNull final String[] paths, @Nullable final String projectReference) {
        final List<Dependency> deps = new ArrayList<>();
        for (String path : paths) {
            final List<Dependency> d = scan(path, projectReference);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param path the path to a file or directory to be analyzed
     * @return the list of dependencies scanned
     */
    public List<Dependency> scan(@NotNull final String path) {
        return scan(path, null);
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param path the path to a file or directory to be analyzed
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    public List<Dependency> scan(@NotNull final String path, String projectReference) {
        final File file = new File(path);
        return scan(file, projectReference);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param files an array of paths to files or directories to be analyzed.
     * @return the list of dependencies
     * @since v0.3.2.5
     */
    public List<Dependency> scan(File[] files) {
        return scan(files, null);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param files an array of paths to files or directories to be analyzed.
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the list of dependencies
     * @since v1.4.4
     */
    public List<Dependency> scan(File[] files, String projectReference) {
        final List<Dependency> deps = new ArrayList<>();
        for (File file : files) {
            final List<Dependency> d = scan(file, projectReference);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a collection of files or directories. If a directory is specified,
     * it will be scanned recursively. Any dependencies identified are added to
     * the dependency collection.
     *
     * @param files a set of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(Collection<File> files) {
        return scan(files, null);
    }

    /**
     * Scans a collection of files or directories. If a directory is specified,
     * it will be scanned recursively. Any dependencies identified are added to
     * the dependency collection.
     *
     * @param files a set of paths to files or directories to be analyzed
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    public List<Dependency> scan(Collection<File> files, String projectReference) {
        final List<Dependency> deps = new ArrayList<>();
        files.stream().map((file) -> scan(file, projectReference))
                .filter(Objects::nonNull)
                .forEach(deps::addAll);
        return deps;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param file the path to a file or directory to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.4
     */
    public List<Dependency> scan(File file) {
        return scan(file, null);
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param file the path to a file or directory to be analyzed
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    @Nullable
    public List<Dependency> scan(@NotNull final File file, String projectReference) {
        if (file.exists()) {
            if (file.isDirectory()) {
                return scanDirectory(file, projectReference);
            } else {
                final Dependency d = scanFile(file, projectReference);
                if (d != null) {
                    final List<Dependency> deps = new ArrayList<>();
                    deps.add(d);
                    return deps;
                }
            }
        }
        return null;
    }

    /**
     * Recursively scans files and directories. Any dependencies identified are
     * added to the dependency collection.
     *
     * @param dir the directory to scan
     * @return the list of Dependency objects scanned
     */
    protected List<Dependency> scanDirectory(File dir) {
        return scanDirectory(dir, null);
    }

    /**
     * Recursively scans files and directories. Any dependencies identified are
     * added to the dependency collection.
     *
     * @param dir the directory to scan
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the list of Dependency objects scanned
     * @since v1.4.4
     */
    protected List<Dependency> scanDirectory(@NotNull final File dir, @Nullable final String projectReference) {
        final File[] files = dir.listFiles();
        final List<Dependency> deps = new ArrayList<>();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    final List<Dependency> d = scanDirectory(f, projectReference);
                    if (d != null) {
                        deps.addAll(d);
                    }
                } else {
                    final Dependency d = scanFile(f, projectReference);
                    if (d != null) {
                        deps.add(d);
                    }
                }
            }
        }
        return deps;
    }

    /**
     * Scans a specified file. If a dependency is identified it is added to the
     * dependency collection.
     *
     * @param file The file to scan
     * @return the scanned dependency
     */
    protected Dependency scanFile(@NotNull final File file) {
        return scanFile(file, null);
    }

    //CSOFF: NestedIfDepth
    /**
     * Scans a specified file. If a dependency is identified it is added to the
     * dependency collection.
     *
     * @param file The file to scan
     * @param projectReference the name of the project or scope in which the
     * dependency was identified
     * @return the scanned dependency
     * @since v1.4.4
     */
    protected synchronized Dependency scanFile(@NotNull final File file, @Nullable final String projectReference) {
        Dependency dependency = null;
        if (file.isFile()) {
            if (accept(file)) {
                dependency = new Dependency(file);
                if (projectReference != null) {
                    dependency.addProjectReference(projectReference);
                }
//                final String sha1 = dependency.getSha1sum();
                boolean found = false;

//                if (sha1 != null) {
//                    for (Dependency existing : dependencies) {
//                        if (sha1.equals(existing.getSha1sum())) {
//                            if (existing.getDisplayFileName().contains(": ")
//                                    || dependency.getDisplayFileName().contains(": ")
//                                    || dependency.getActualFilePath().contains("dctemp")) {
//                                continue;
//                            }
//                            found = true;
//                            if (projectReference != null) {
//                                existing.addProjectReference(projectReference);
//                            }
//                            if (existing.getActualFilePath() != null && dependency.getActualFilePath() != null
//                                    && !existing.getActualFilePath().equals(dependency.getActualFilePath())) {
//
//                                if (DependencyBundlingAnalyzer.firstPathIsShortest(existing.getFilePath(), dependency.getFilePath())) {
//                                    DependencyBundlingAnalyzer.mergeDependencies(existing, dependency, null);
//
//                                    //return null;
//                                    return existing;
//                                } else {
//                                    //Merging dependency<-existing could be complicated. Instead analyze them seperately
//                                    //and possibly merge them at the end.
//                                    found = false;
//                                }
//
//                            } else { //somehow we scanned the same file twice?
//                                //return null;
//                                return existing;
//                            }
//                            break;
//                        }
//                    }
//                }
                if (!found) {
                    dependencies.add(dependency);
                    dependenciesExternalView = null;
                }
            }
        } else {
            LOGGER.debug("Path passed to scanFile(File) is not a file that can be scanned by dependency-check: {}. Skipping the file.", file);
        }
        return dependency;
    }
    //CSON: NestedIfDepth

    /**
     * Runs the analyzers against all of the dependencies. Since the mutable
     * dependencies list is exposed via {@link #getDependencies()}, this method
     * iterates over a copy of the dependencies list. Thus, the potential for
     * {@link java.util.ConcurrentModificationException}s is avoided, and
     * analyzers may safely add or remove entries from the dependencies list.
     * <p>
     * Every effort is made to complete analysis on the dependencies. In some
     * cases an exception will occur with part of the analysis being performed
     * which may not affect the entire analysis. If an exception occurs it will
     * be included in the thrown exception collection.
     *
     * @throws ExceptionCollection a collections of any exceptions that occurred
     * during analysis
     */
    public void analyzeDependencies(String markfile) throws ExceptionCollection {
        final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<>());

        MARKFILE = markfile;
        //初始化并更新CVE库
        //initializeAndUpdateDatabase(exceptions);

        //need to ensure that data exists
//        try {
//            ensureDataExists();
//        } catch (NoDataException ex) {
//            throwFatalExceptionCollection("Unable to continue dependency-check analysis.", ex, exceptions);
//        }
        LOGGER.debug("\n----------------------------------------------------\nBEGIN ANALYSIS\n----------------------------------------------------");
        LOGGER.info("Analysis Started");
        final long analysisStart = System.currentTimeMillis();

        // analysis phases
        for (AnalysisPhase phase : mode.getPhases()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);

            for (final Analyzer analyzer : analyzerList) {
                final long analyzerStart = System.currentTimeMillis();
                try {
                    initializeAnalyzer(analyzer);
                } catch (InitializationException ex) {
                    exceptions.add(ex);
                    if (ex.isFatal()) {
                        continue;
                    }
                }

                if (analyzer.isEnabled()) {
                    executeAnalysisTasks(analyzer, exceptions);

                    final long analyzerDurationMillis = System.currentTimeMillis() - analyzerStart;
                    final long analyzerDurationSeconds = TimeUnit.MILLISECONDS.toSeconds(analyzerDurationMillis);
                    LOGGER.info("Finished {} ({} seconds)", analyzer.getName(), analyzerDurationSeconds);
                } else {
                    LOGGER.debug("Skipping {} (not enabled)", analyzer.getName());
                }
            }
        }
        mode.getPhases().stream()
                .map(analyzers::get)
                .forEach((analyzerList) -> analyzerList.forEach(this::closeAnalyzer));

        SuppressionRules.getInstance().logUnusedRules();

        LOGGER.debug("\n----------------------------------------------------\nEND ANALYSIS\n----------------------------------------------------");
        final long analysisDurationSeconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - analysisStart);
        LOGGER.info("Analysis Complete ({} seconds)", analysisDurationSeconds);
        if (exceptions.size() > 0) {
            throw new ExceptionCollection(exceptions);
        }
    }

    /**
     * Executes executes the analyzer using multiple threads.
     *
     * @param exceptions a collection of exceptions that occurred during
     * analysis
     * @param analyzer the analyzer to execute
     * @throws ExceptionCollection thrown if exceptions occurred during analysis
     */
    protected void executeAnalysisTasks(@NotNull final Analyzer analyzer, List<Throwable> exceptions) throws ExceptionCollection {
        LOGGER.debug("Starting {}", analyzer.getName());
        final List<AnalysisTask> analysisTasks = getAnalysisTasks(analyzer, exceptions);
        final ExecutorService executorService = getExecutorService(analyzer);

        try {
            final int timeout = settings.getInt(Settings.KEYS.ANALYSIS_TIMEOUT, 180);
            final List<Future<Void>> results = executorService.invokeAll(analysisTasks, timeout, TimeUnit.MINUTES);

            // ensure there was no exception during execution
            for (Future<Void> result : results) {
                try {
                    result.get();
                } catch (ExecutionException e) {
                    throwFatalExceptionCollection("Analysis task failed with a fatal exception.", e, exceptions);
                } catch (CancellationException e) {
                    throwFatalExceptionCollection("Analysis task was cancelled.", e, exceptions);
                }
            }
            //建立依赖树
            if(analyzer.getName()=="Jar Analyzer"){
//                buildDependencyTree();

                try {
                    JarAnalyzer jarAnalyzer =new JarAnalyzer();

                    int index = 0;
                    for (Dependency dependency : dependencies
                    ) {
                        jarAnalyzer.analyzeIntro(dependency, dependencies, index++,MARKFILE);
                    }

                    jarAnalyzer.detectNPIJar(dependencies);

                }
                catch (Exception e) {
                    e.printStackTrace();
                }



            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throwFatalExceptionCollection("Analysis has been interrupted.", e, exceptions);
        } finally {
            executorService.shutdown();
        }
    }

    /**
     * Returns the analysis tasks for the dependencies.
     *
     * @param analyzer the analyzer to create tasks for
     * @param exceptions the collection of exceptions to collect
     * @return a collection of analysis tasks
     */
    protected synchronized List<AnalysisTask> getAnalysisTasks(Analyzer analyzer, List<Throwable> exceptions) {
        final List<AnalysisTask> result = new ArrayList<>();
        dependencies.stream().map((dependency) -> new AnalysisTask(analyzer, dependency, this, exceptions)).forEach(result::add);
        return result;
    }

    /**
     * Returns the executor service for a given analyzer.
     *
     * @param analyzer the analyzer to obtain an executor
     * @return the executor service
     */
    protected ExecutorService getExecutorService(Analyzer analyzer) {
        if (analyzer.supportsParallelProcessing()) {
            final int maximumNumberOfThreads = Runtime.getRuntime().availableProcessors();
            LOGGER.debug("Parallel processing with up to {} threads: {}.", maximumNumberOfThreads, analyzer.getName());
            return Executors.newFixedThreadPool(maximumNumberOfThreads);
        } else {
            LOGGER.debug("Parallel processing is not supported: {}.", analyzer.getName());
            return Executors.newSingleThreadExecutor();
        }
    }

    /**
     * Initializes the given analyzer.
     *
     * @param analyzer the analyzer to prepare
     * @throws InitializationException thrown when there is a problem
     * initializing the analyzer
     */
    protected void initializeAnalyzer(@NotNull final Analyzer analyzer) throws InitializationException {
        try {
            LOGGER.debug("Initializing {}", analyzer.getName());
            analyzer.prepare(this);
        } catch (InitializationException ex) {
            LOGGER.error("Exception occurred initializing {}.", analyzer.getName());
            LOGGER.debug("", ex);
            if (ex.isFatal()) {
                try {
                    analyzer.close();
                } catch (Throwable ex1) {
                    LOGGER.trace("", ex1);
                }
            }
            throw ex;
        } catch (Throwable ex) {
            LOGGER.error("Unexpected exception occurred initializing {}.", analyzer.getName());
            LOGGER.debug("", ex);
            try {
                analyzer.close();
            } catch (Throwable ex1) {
                LOGGER.trace("", ex1);
            }
            throw new InitializationException("Unexpected Exception", ex);
        }
    }

    /**
     * Closes the given analyzer.
     *
     * @param analyzer the analyzer to close
     */
    protected void closeAnalyzer(@NotNull final Analyzer analyzer) {
        LOGGER.debug("Closing Analyzer '{}'", analyzer.getName());
        try {
            analyzer.close();
        } catch (Throwable ex) {
            LOGGER.trace("", ex);
        }
    }



    /**
     * Returns a full list of all of the analyzers. This is useful for reporting
     * which analyzers where used.
     *
     * @return a list of Analyzers
     */
    @NotNull
    public List<Analyzer> getAnalyzers() {
        final List<Analyzer> analyzerList = new ArrayList<>();
        //insteae of forEach - we can just do a collect
        mode.getPhases().stream()
                .map(analyzers::get)
                .forEachOrdered(analyzerList::addAll);
        return analyzerList;
    }

    /**
     * Checks all analyzers to see if an extension is supported.
     *
     * @param file a file extension
     * @return true or false depending on whether or not the file extension is
     * supported
     */
    @Override
    public boolean accept(@Nullable final File file) {
        if (file == null) {
            return false;
        }
        /* note, we can't break early on this loop as the analyzers need to know if
        they have files to work on prior to initialization */
        return this.fileTypeAnalyzers.stream().map((a) -> a.accept(file)).reduce(false, (accumulator, result) -> accumulator || result);
    }

    /**
     * Returns the set of file type analyzers.
     *
     * @return the set of file type analyzers
     */
    public Set<FileTypeAnalyzer> getFileTypeAnalyzers() {
        return this.fileTypeAnalyzers;
    }

    /**
     * Returns the configured settings.
     *
     * @return the configured settings
     */
    public Settings getSettings() {
        return settings;
    }

    /**
     * Returns the mode of the engine.
     *
     * @return the mode of the engine
     */
    public Mode getMode() {
        return mode;
    }

    /**
     * Adds a file type analyzer. This has been added solely to assist in unit
     * testing the Engine.
     *
     * @param fta the file type analyzer to add
     */
    protected void addFileTypeAnalyzer(@NotNull final FileTypeAnalyzer fta) {
        this.fileTypeAnalyzers.add(fta);
    }

    /**
     * Constructs and throws a fatal exception collection.
     *
     * @param message the exception message
     * @param throwable the cause
     * @param exceptions a collection of exception to include
     * @throws ExceptionCollection a collection of exceptions that occurred
     * during analysis
     */
    private void throwFatalExceptionCollection(String message, @NotNull final Throwable throwable,
                                               @NotNull final List<Throwable> exceptions) throws ExceptionCollection {
        LOGGER.error(message);
        LOGGER.debug("", throwable);
        exceptions.add(throwable);
        throw new ExceptionCollection(exceptions, true);
    }

    /**
     * Writes the report to the given output directory.
     *
     * @param applicationName the name of the application/project
     * @param outputDir the path to the output directory (can include the full
     * file name if the format is not ALL)
     * @param format the report format (ALL, HTML, CSV, JSON, etc.)
     * @throws ReportException thrown if there is an error generating the report
     * @deprecated use
     * {@link #writeReports(String, File, String, ExceptionCollection)}
     */
    @Deprecated
    public void writeReports(String applicationName, File outputDir, String format) throws ReportException {
        writeReports(applicationName, null, null, null, outputDir, format, null);
    }

    //CSOFF: LineLength
    /**
     * Writes the report to the given output directory.
     *
     * @param applicationName the name of the application/project
     * @param outputDir the path to the output directory (can include the full
     * file name if the format is not ALL)
     * @param format the report format (ALL, HTML, CSV, JSON, etc.)
     * @param exceptions a collection of exceptions that may have occurred
     * during the analysis
     * @throws ReportException thrown if there is an error generating the report
     */
    public void writeReports(String applicationName, File outputDir, String format, ExceptionCollection exceptions) throws ReportException {
        writeReports(applicationName, null, null, null, outputDir, format, exceptions);
    }
    //CSON: LineLength

    /**
     * Writes the report to the given output directory.
     *
     * @param applicationName the name of the application/project
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the Maven version
     * @param outputDir the path to the output directory (can include the full
     * file name if the format is not ALL)
     * @param format the report format (ALL, HTML, CSV, JSON, etc.)
     * @throws ReportException thrown if there is an error generating the report
     * @deprecated use
     * {@link #writeReports(String, String, String, String, File, String, ExceptionCollection)}
     */
    @Deprecated
    public synchronized void writeReports(String applicationName, @Nullable final String groupId,
                                          @Nullable final String artifactId, @Nullable final String version,
                                          @NotNull final File outputDir, String format) throws ReportException {
        writeReports(applicationName, groupId, artifactId, version, outputDir, format, null);
    }

    //CSOFF: LineLength
    /**
     * Writes the report to the given output directory.
     *
     * @param applicationName the name of the application/project
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the Maven version
     * @param outputDir the path to the output directory (can include the full
     * file name if the format is not ALL)
     * @param format the report format (ALL, HTML, CSV, JSON, etc.)
     * @param exceptions a collection of exceptions that may have occurred
     * during the analysis
     * @throws ReportException thrown if there is an error generating the report
     */
    public synchronized void writeReports(String applicationName, @Nullable final String groupId,
                                          @Nullable final String artifactId, @Nullable final String version,
                                          @NotNull final File outputDir, String format, ExceptionCollection exceptions) throws ReportException {
        if (mode == Mode.EVIDENCE_COLLECTION) {
            throw new UnsupportedOperationException("Cannot generate report in evidence collection mode.");
        }
//        final DatabaseProperties prop = database.getDatabaseProperties();
        final ReportGenerator r = new ReportGenerator(applicationName, groupId, artifactId, version,
                dependencies, getAnalyzers(),  settings, exceptions);
        try {
            r.write(outputDir.getAbsolutePath(), format);
        } catch (ReportException ex) {
            final String msg = String.format("Error generating the report for %s", applicationName);
            LOGGER.debug(msg, ex);
            throw new ReportException(msg, ex);
        }
    }
    //CSON: LineLength

    public File creatSJsonFile(String path){
        try {
            File file = new File(path);


            if (!file.getParentFile().exists()) { // 如果父目录不存在，创建父目录
                file.getParentFile().mkdirs();
            }
            if (file.exists()) { // 如果已存在,删除旧文件
                file.delete();
            }
            file.createNewFile();
            return file;
        }        catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    public void writeJsonFile(File file , JSONObject root){
        try {
            String jsonString1 = formatJson(root.toString());
            // 将格式化后的字符串写入文件
            Writer write1 = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
            write1.write(jsonString1);
            write1.flush();
            write1.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    /**
     * 构建依赖树。
     */
    protected void buildDependencyTree() throws XmlPullParserException {


        HashSet<String> groups = new HashSet<>();
//
        JarAnalyzer jarAnalyzer =new JarAnalyzer();
//
        JSONObject root1 = new JSONObject();
        JSONObject root2 = new JSONObject();
        JSONObject root3 = new JSONObject();
        JSONObject root4 = new JSONObject();

        JSONArray nodes = new JSONArray();
        JSONArray combos = new JSONArray();


        String nodePath = "./node.json";
        String edgePath = "./comboedge.json";
        String comboPath = "./combo.json";
        String nodEedgePath = "./nodeedge.json";


        try {
            File file1 = creatSJsonFile(nodePath);
            File file2 = creatSJsonFile(edgePath);
            File file3 = creatSJsonFile(comboPath);
            File file4 = creatSJsonFile(nodEedgePath);
//
//
//
//
//
            int index = 0;
            for (Dependency dependency : dependencies
            ) {

                //
                jarAnalyzer.analyzeIntro(dependency, dependencies, index++, MARKFILE);





                if(!groups.contains(dependency.Groupname))
                {

                    JSONObject node = new JSONObject();
                    JSONObject combo = new JSONObject();
                    node.put("id",  dependency.getDisplayFileName());
                    node.put("level", dependency.level);

                    node.put("label", dependency.artifactid);
                    node.put("comboId", dependency.Groupname);
                    node.put("mark", 0);
//                   if(dependency.level=="own")
//                       combo.put("comboId","own");
//                   else if(dependency.level=="direct")
//                       combo.put("comboId","direct");
//                   else    if(dependency.level=="third")                     combo.put("comboId","third");
//                   else combo.put("comboId","four");
//                   combo.put("")


//                    node.put("level", dependency.level);
                    combo.put("label", dependency.Groupname);
                    combo.put("id", dependency.Groupname);
                    combo.put("comboId", dependency.level);
                    combo.put("mark",0);


                    nodes.put(node);
                    combos.put(combo);
                    groups.add(dependency.Groupname);

                }

                else{
                    JSONObject node = new JSONObject();

                    node.put("id",  dependency.getDisplayFileName());
                    node.put("level", dependency.level);
                    node.put("mark", 0);
                    node.put("label", dependency.getDisplayFileName());
                    node.put("comboId", dependency.Groupname);
                    nodes.put(node);


                }




            }


            root1.put("nodes", nodes);
            writeJsonFile(file1,root1);

            JSONArray edges = new JSONArray();
            JSONArray nodeEdges = new JSONArray();

            //加边
            jarAnalyzer.topoSort(edges,nodeEdges,dependencies);


            root2.put("comboNodeEdges", edges);
            writeJsonFile(file2,root2);

            root3.put("comboNodes", combos);

            writeJsonFile(file3,root3);




            root4.put("nodeEdges", nodeEdges);
            writeJsonFile(file4,root4);

        }
        catch (Exception e) {
            e.printStackTrace();
        }



    }



    /**
     * {@link Engine} execution modes.
     */
    public enum Mode {
        /**
         * In evidence collection mode the {@link Engine} only collects evidence
         * from the scan targets, and doesn't require a database.
         */
        EVIDENCE_COLLECTION(
                false,
                INITIAL,
                PRE_INFORMATION_COLLECTION,
                INFORMATION_COLLECTION,
                INFORMATION_COLLECTION2,
                POST_INFORMATION_COLLECTION
        ),
        /**
         * In evidence processing mode the {@link Engine} processes the evidence
         * collected using the {@link #EVIDENCE_COLLECTION} mode. Dependencies
         * should be injected into the {@link Engine} using
         * {@link Engine#setDependencies(List)}.
         */
        EVIDENCE_PROCESSING(
                true,
                PRE_IDENTIFIER_ANALYSIS,
                IDENTIFIER_ANALYSIS,
                POST_IDENTIFIER_ANALYSIS,
                PRE_FINDING_ANALYSIS,
                FINDING_ANALYSIS,
                POST_FINDING_ANALYSIS,
                FINDING_ANALYSIS_PHASE2,
                FINAL
        ),
        /**
         * In standalone mode the {@link Engine} will collect and process
         * evidence in a single execution.
         */
        STANDALONE(true, AnalysisPhase.values());

        /**
         * Whether the database is required in this mode.
         */
        private final boolean databaseRequired;
        /**
         * The analysis phases included in the mode.
         */
        private final List<AnalysisPhase> phases;

        /**
         * Constructs a new mode.
         *
         * @param databaseRequired if the database is required for the mode
         * @param phases the analysis phases to include in the mode
         */
        Mode(boolean databaseRequired, AnalysisPhase... phases) {
            this.databaseRequired = databaseRequired;
            this.phases = Collections.unmodifiableList(Arrays.asList(phases));
        }

        /**
         * Returns true if the database is required; otherwise false.
         *
         * @return whether or not the database is required
         */
        private boolean isDatabaseRequired() {
            return databaseRequired;
        }

        /**
         * Returns the phases for this mode.
         *
         * @return the phases for this mode
         */
        public List<AnalysisPhase> getPhases() {
            return phases;
        }


    }
}