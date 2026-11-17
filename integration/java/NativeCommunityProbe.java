package aria;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/** Native-runtime measurement only. Never sends an HTTP request through Burp. */
public final class NativeCommunityProbe implements BurpExtension {
    private final AtomicInteger requests = new AtomicInteger();
    private Path output;

    private void recordCount() {
        try { Files.writeString(output.resolve("native-request-count.json"),
                "{\"burp_http_requests\":" + requests.get() + "}"); }
        catch (Exception failure) { throw new IllegalStateException("Probe evidence unavailable", failure); }
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n") + "\"";
    }

    @Override public void initialize(MontoyaApi api) {
        output = Path.of(System.getenv("ARIA_NATIVE_PROBE_OUTPUT"));
        try {
            var version = api.burpSuite().version();
            Files.writeString(output.resolve("native-version.json"), "{\"name\":" + quote(version.name())
                + ",\"display\":" + quote(version.toString())
                + ",\"major\":" + quote(version.major()) + ",\"minor\":" + quote(version.minor())
                + ",\"build\":" + quote(version.build()) + ",\"build_number\":" + version.buildNumber()
                + ",\"edition\":" + quote(version.edition().name()) + "}");
            api.http().registerHttpHandler(new HttpHandler() {
                @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                    requests.incrementAndGet(); recordCount();
                    return RequestToBeSentAction.continueWith(request);
                }
                @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                    return ResponseReceivedAction.continueWith(response);
                }
            });
            recordCount();
            new CommunityExtension().initialize(api);
        } catch (Exception failure) {
            throw new IllegalStateException("Native compatibility probe could not initialize", failure);
        }
    }
}
