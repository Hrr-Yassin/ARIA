package aria;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Disposable protocol fixture. Not an extension entry point and never auto-started. */
public final class ReplayFixtureServer {
    public static void main(String[] args) throws Exception {
        String token=System.getenv("ARIA_FIXTURE_TOKEN");
        AtomicInteger calls=new AtomicInteger();
        final byte[][] captured={new byte[0]};
        var boundary=new ReplayBoundary(token,Set.of("192.0.2.1"),Path.of(args[0]),(host,port,raw,timeout)->{
            calls.incrementAndGet(); captured[0]=raw;
            if(new String(raw,StandardCharsets.ISO_8859_1).contains(" /slow ")) Thread.sleep(15000);
            return "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nfixture".getBytes(StandardCharsets.ISO_8859_1);
        });
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),10);
        server.createContext("/",exchange->{
            try {
                if(!MessageDigest.isEqual(("Bearer "+token).getBytes(StandardCharsets.UTF_8),Objects.toString(exchange.getRequestHeaders().getFirst("Authorization"),"").getBytes(StandardCharsets.UTF_8))) {
                    exchange.sendResponseHeaders(403,-1); return;
                }
                if(boundary.handle(exchange)) return;
                String body=exchange.getRequestURI().getPath().equals("/stats")?
                    "{\"calls\":"+calls.get()+",\"captured_b64\":\""+Base64.getEncoder().encodeToString(captured[0])+"\"}":
                    "{\"edition\":\"COMMUNITY\",\"active_replay\":true,\"scanner\":false}";
                byte[] output=body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type","application/json"); exchange.sendResponseHeaders(200,output.length); exchange.getResponseBody().write(output);
            } catch(Exception failure) { exchange.sendResponseHeaders(422,-1); }
            finally { exchange.close(); }
        });
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(()->{server.stop(0);boundary.close();}));
        System.out.println(server.getAddress().getPort());
        System.out.flush();
    }
}
