public class Job {
    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger("job");
    void run() {
        try { charge(); } catch (Exception e) { LOG.severe("charge failed: " + e.getClass().getName()); throw new IllegalStateException(e); }
    }
    void charge() throws Exception {}
}
