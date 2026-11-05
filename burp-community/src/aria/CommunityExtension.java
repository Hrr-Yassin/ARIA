package aria;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import java.awt.Component;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sun.net.httpserver.HttpServer;
import javax.swing.*;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Community-only selection exporter and passive Repeater staging connector. */
public final class CommunityExtension implements BurpExtension {
    private MontoyaApi api;
    private HttpServer server;
    private ExecutorService executor;
    private String connectorToken;
    private ReplayBoundary replay;
    private final Set<String> staged = ConcurrentHashMap.newKeySet();
    private final Set<String> targets = new HashSet<>();
    private static final String BASE = "http://127.0.0.1:7000";

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("ARIA Community evidence connector");
        if (api.burpSuite().version().edition()!=burp.api.montoya.core.BurpSuiteEdition.COMMUNITY_EDITION) {
            api.logging().logToError("ARIA connector requires Burp Community Edition."); return;
        }
        if("1".equals(System.getenv("ARIA_BURP_SET_SCOPE"))) {
            for(String target:System.getenv().getOrDefault("ARIA_BURP_TARGETS","192.168.77.20").split(",")) api.scope().includeInScope("http://"+target+"/");
            api.proxy().disableIntercept();
        }
        connectorToken = System.getenv("ARIA_BURP_CONNECTOR_TOKEN");
        targets.addAll(Arrays.asList(System.getenv().getOrDefault("ARIA_BURP_TARGETS", "192.168.77.20").split(",")));
        if (connectorToken == null || connectorToken.length() < 32) {
            api.logging().logToError("Configure ARIA_BURP_CONNECTOR_TOKEN (at least 32 characters)."); return;
        }
        try {
            replay = new ReplayBoundary(connectorToken,targets,java.nio.file.Path.of(System.getenv().getOrDefault("ARIA_BURP_STATE_FILE",System.getProperty("user.home")+"/.aria/burp-replay.properties")),
                (target,port,raw,timeout) -> {
                    var request=HttpRequest.httpRequest(HttpService.httpService(target,port,false),ByteArray.byteArray(raw));
                    var options=burp.api.montoya.http.RequestOptions.requestOptions().withResponseTimeout(timeout)
                        .withRedirectionMode(burp.api.montoya.http.RedirectionMode.NEVER);
                    var pair=api.http().sendRequest(request,options);
                    if(pair.response()==null) throw new IllegalStateException();
                    return pair.response().toByteArray().getBytes();
                });
            server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),17777),10);
            executor = Executors.newFixedThreadPool(2);
            server.setExecutor(executor);
            server.createContext("/", exchange -> {
                try {
                    String auth = exchange.getRequestHeaders().getFirst("Authorization");
                    if (!MessageDigest.isEqual(("Bearer "+connectorToken).getBytes(StandardCharsets.UTF_8),
                            Objects.toString(auth, "").getBytes(StandardCharsets.UTF_8)) || exchange.getRequestHeaders().containsKey("Origin")) {
                        exchange.sendResponseHeaders(403,-1); return;
                    }
                    if(replay.handle(exchange)) return;
                    if(handleHistory(exchange)) return;
                    String path = exchange.getRequestURI().getPath();
                    if (path.equals("/capabilities") && exchange.getRequestMethod().equals("GET")) {
                        var ports=new ArrayList<String>();
                        var matcher=java.util.regex.Pattern.compile("\\\"listener_port\\\"\\s*:\\s*(\\d+)").matcher(api.burpSuite().exportProjectOptionsAsJson());
                        while(matcher.find()) ports.add(matcher.group(1));
                        reply(exchange, "{\"edition\":\"COMMUNITY\",\"scanner\":false,\"active_replay\":true,\"repeater_staging\":true,\"proxy_ports\":["+String.join(",",ports)+"]}"); return;
                    }
                    if (!path.equals("/repeater") || !exchange.getRequestMethod().equals("POST")) {
                        exchange.sendResponseHeaders(404,-1); return;
                    }
                    byte[] input = exchange.getRequestBody().readNBytes(100001);
                    if (input.length>100000) { exchange.sendResponseHeaders(413,-1); return; }
                    Map<String,String> form = new HashMap<>();
                    for (String pair : new String(input,StandardCharsets.UTF_8).split("&")) {
                        String[] parts=pair.split("=",2);
                        if (parts.length==2) form.put(URLDecoder.decode(parts[0],StandardCharsets.UTF_8),URLDecoder.decode(parts[1],StandardCharsets.UTF_8));
                    }
                    URI url = URI.create(form.get("url"));
                    validate(url);
                    byte[] raw=Base64.getDecoder().decode(form.get("request_b64"));
                    if(raw.length>65536) throw new IllegalArgumentException();
                    String id=form.get("evidence_id");
                    UUID.fromString(id);
                    // Staging is passive: Burp issues nothing until the user presses Send.
                    synchronized(staged) {
                        if (!staged.contains(id)) {
                            if(staged.size()>=20) { exchange.sendResponseHeaders(429,-1); return; }
                            HttpRequest request=HttpRequest.httpRequest(HttpService.httpService(url.getHost(),80,false),ByteArray.byteArray(raw));
                            SwingUtilities.invokeAndWait(() -> api.repeater().sendToRepeater(request,"ARIA "+id.substring(0,8)));
                            staged.add(id);
                        }
                    }
                    reply(exchange,"{\"status\":\"staged\",\"network_request_sent\":false}");
                } catch(Exception failure) { exchange.sendResponseHeaders(422,-1); }
                finally { exchange.close(); }
            });
            server.start();
            api.extension().registerUnloadingHandler(() -> { server.stop(0); executor.shutdownNow(); replay.close(); });
        } catch(Exception failure) { api.logging().logToError("Could not start loopback connector on port 17777."); return; }
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
            JMenuItem item=new JMenuItem("Import selected pairs into ARIA engagement");
            item.addActionListener(ignored -> {
                var selection=List.copyOf(event.selectedRequestResponses());
                if(selection.isEmpty() || selection.size()>20) {
                    JOptionPane.showMessageDialog(null,"Select 1–20 in-scope HTTP pairs."); return;
                }
                String session=JOptionPane.showInputDialog("Owning ARIA engagement UUID:");
                try { UUID.fromString(session); } catch(Exception invalid) { return; }
                executor.submit(() -> {
                    String userToken=System.getenv("ARIA_BURP_USER_TOKEN");
                    if(userToken==null) { api.logging().logToError("ARIA_BURP_USER_TOKEN is not configured."); return; }
                    try {
                        HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
                        for(var pair:selection) {
                            String url=pair.request().url(); validate(URI.create(url));
                            if(!api.scope().isInScope(url)) throw new IllegalArgumentException();
                            String request=Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                            String response=pair.response()==null?"":Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());
                            String body="{\"url\":"+quote(url)+",\"request_b64\":"+quote(request)+",\"response_b64\":"+quote(response)+"}";
                            var message=java.net.http.HttpRequest.newBuilder(URI.create(BASE+"/api/burp/"+session+"/import"))
                                .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+userToken)
                                .header("Content-Type","application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build();
                            var result=client.send(message,java.net.http.HttpResponse.BodyHandlers.discarding());
                            if(result.statusCode()!=200) throw new IllegalArgumentException();
                        }
                        api.logging().logToOutput("Selected pairs imported into their owning engagement.");
                    } catch(Exception failure) { api.logging().logToError("Import refused or connector disconnected; inspect ARIA status without exposing original requests."); }
                });
            });
            return List.of(item);
            }
        });
    }

    private boolean handleHistory(com.sun.net.httpserver.HttpExchange exchange) throws Exception {
        String path=exchange.getRequestURI().getPath();
        boolean selection=path.equals("/history/selected") && exchange.getRequestMethod().equals("POST");
        if(!selection && !(path.equals("/history") && exchange.getRequestMethod().equals("GET"))) return false;
        Set<String> ids=selection?new HashSet<>(Arrays.asList(ReplayBoundary.readForm(exchange).getOrDefault("ids","").split(","))):Set.of();
        if(selection && (ids.isEmpty() || ids.size()>20 || ids.contains(""))) throw new IllegalArgumentException();
        List<String> entries=new ArrayList<>();
        Set<String> seen=new HashSet<>();
        var history=api.proxy().history();
        for(int index=Math.max(0,history.size()-100);index<history.size();index++) {
            var pair=history.get(index);
            String url=pair.request().url();
            try { validate(URI.create(url)); if(!api.scope().isInScope(url)) continue; }
            catch(IllegalArgumentException refused) { continue; }
            byte[] request=pair.request().toByteArray().getBytes();
            byte[] response=pair.response()==null?new byte[0]:pair.response().toByteArray().getBytes();
            var mac=javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(connectorToken.getBytes(StandardCharsets.UTF_8),"HmacSHA256"));
            mac.update(request); mac.update((byte)0); mac.update(response);
            String id=HexFormat.of().formatHex(mac.doFinal());
            if(!seen.add(id)) continue;
            if(selection) {
                if(!ids.contains(id)) continue;
                if(request.length>65536 || response.length>1048576) throw new IllegalArgumentException();
                entries.add("{\"capture_id\":"+quote(id)+",\"url\":"+quote(url)+",\"request_b64\":"+quote(Base64.getEncoder().encodeToString(request))+",\"response_b64\":"+quote(Base64.getEncoder().encodeToString(response))+"}");
            } else {
                URI parsed=URI.create(url);
                String endpoint="http://"+parsed.getRawAuthority()+(parsed.getRawPath()==null?"/":parsed.getRawPath());
                entries.add("{\"capture_id\":"+quote(id)+",\"url\":"+quote(endpoint)+",\"method\":"+quote(pair.request().method())+"}");
            }
        }
        if(selection && entries.size()!=ids.size()) throw new IllegalArgumentException();
        reply(exchange,"{\"captures\":["+String.join(",",entries)+"]}");
        return true;
    }

    private void validate(URI url) {
        if(!"http".equals(url.getScheme()) || !targets.contains(url.getHost()) || (url.getPort()!=-1 && url.getPort()!=80)
                || url.getUserInfo()!=null || url.getFragment()!=null) throw new IllegalArgumentException();
    }
    private static String quote(String value) {
        StringBuilder result=new StringBuilder("\"");
        for(char c:value.toCharArray()) {
            if(c=='"' || c=='\\') result.append('\\').append(c);
            else if(c<32) result.append(String.format("\\u%04x",(int)c));
            else result.append(c);
        }
        return result.append('"').toString();
    }
    private static void reply(com.sun.net.httpserver.HttpExchange exchange,String json) throws java.io.IOException {
        byte[] output=json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(200,output.length); exchange.getResponseBody().write(output);
    }
}
