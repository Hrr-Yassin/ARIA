package aria;

import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Durable one-use admission. Cancellation stays pending until the sender returns. */
public final class ReplayBoundary implements AutoCloseable {
    public interface Sender { byte[] send(String target, int port, byte[] request, int timeoutMs) throws Exception; }
    private static final class Job {
        String id, session, hash, state="queued";
        volatile boolean cancelling;
        volatile byte[] response;
        Future<?> task;
    }
    private final Map<String,Job> jobs=new HashMap<>();
    private final Properties ledger=new Properties();
    private final Path path;
    private final String token;
    private final Set<String> targets;
    private final Sender sender;
    private final ExecutorService workers=Executors.newFixedThreadPool(2);
    private final ScheduledExecutorService deadlines=Executors.newSingleThreadScheduledExecutor();

    public ReplayBoundary(String token, Set<String> targets, Path path, Sender sender) throws Exception {
        this.token=token; this.targets=Set.copyOf(targets); this.path=path; this.sender=sender;
        if(Files.exists(path)) try(InputStream input=Files.newInputStream(path)) { ledger.load(input); }
        for(String key:ledger.stringPropertyNames()) if(key.endsWith(".session")) {
            String id=key.substring(0,key.length()-8);
            Job job=new Job(); job.id=id; job.session=ledger.getProperty(key); job.hash=ledger.getProperty(id+".hash");
            String previous=ledger.getProperty(id+".state","unknown");
            job.state=Set.of("failed","cancelled").contains(previous)?previous:"unknown";
            jobs.put(id,job);
        }
    }

    public boolean handle(HttpExchange exchange) throws Exception {
        String route=exchange.getRequestURI().getPath();
        if(!route.equals("/jobs") && !route.startsWith("/jobs/")) return false;
        String method=exchange.getRequestMethod();
        if(route.equals("/jobs") && method.equals("POST")) {
            Map<String,String> form=readForm(exchange);
            Job job=submit(form);
            reply(exchange,snapshot(job)); return true;
        }
        String[] parts=route.split("/");
        if(parts.length<3) throw new IllegalArgumentException();
        UUID.fromString(parts[2]);
        Job job;
        synchronized(this) { job=jobs.get(parts[2]); }
        if(job==null) { exchange.sendResponseHeaders(404,-1); return true; }
        if(parts.length==4 && parts[3].equals("cancel") && method.equals("POST")) cancel(job);
        else if(parts.length!=3 || !method.equals("GET")) { exchange.sendResponseHeaders(405,-1); return true; }
        reply(exchange,snapshot(job)); return true;
    }

    private synchronized Job submit(Map<String,String> form) throws Exception {
        String id=form.get("action_id"),session=form.get("session_id"),hash=form.get("request_digest"),target=form.get("target");
        UUID.fromString(id); UUID.fromString(session);
        int port=Integer.parseInt(form.get("port")), timeout=Integer.parseInt(form.get("timeout_ms")),budget=Integer.parseInt(form.get("budget"));
        long expiry=Long.parseLong(form.get("expires_at")),now=Instant.now().getEpochSecond();
        if(port!=80 || timeout<1 || timeout>10000 || budget<1 || budget>20 || expiry<now || expiry>now+610 || !targets.contains(target)) throw new IllegalArgumentException();
        String signed=String.join("\n",id,session,hash,target,""+port,""+timeout,""+expiry,""+budget);
        Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8),"HmacSHA256"));
        String expected=HexFormat.of().formatHex(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
        if(!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),form.getOrDefault("permit","").getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException();
        byte[] raw=Base64.getDecoder().decode(form.get("request_b64"));
        if(raw.length>65536 || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)).equals(hash)) throw new IllegalArgumentException();
        validateRequest(raw,target);
        Job previous=jobs.get(id);
        if(previous!=null) {
            if(!previous.hash.equals(hash) || !previous.session.equals(session)) throw new IllegalArgumentException();
            return previous;
        }
        long consumed=jobs.values().stream().filter(job -> job.session.equals(session)).count();
        boolean busy=jobs.values().stream().anyMatch(job -> job.session.equals(session) && Set.of("queued","running","cancel_requested").contains(job.state));
        if(consumed>=budget || busy) throw new IllegalStateException("Request budget or active job boundary refused admission");
        Job job=new Job(); job.id=id; job.session=session; job.hash=hash;
        jobs.put(id,job);
        try { persist(job); } catch(Exception failure) { jobs.remove(id); throw failure; }
        job.task=workers.submit(() -> {
            synchronized(this) {
                if(job.cancelling) { job.state="cancelled"; persistQuietly(job); return; }
                job.state="running";
                try { persist(job); } catch(Exception failure) { job.state="unknown"; return; }
            }
            try {
                byte[] response=sender.send(target,port,raw,timeout);
                synchronized(this) {
                    if(response==null || response.length>1048576) throw new IllegalArgumentException();
                    if(job.cancelling) job.state="cancelled";
                    else { job.response=response; job.state="completed"; }
                }
            } catch(Exception failure) {
                synchronized(this) { job.state=job.cancelling?"cancelled":"failed"; }
            } finally {
                synchronized(this) { persistQuietly(job); }
            }
        });
        deadlines.schedule(() -> { synchronized(this) {
            if(Set.of("queued","running").contains(job.state)) cancel(job);
        } },timeout+2000L,TimeUnit.MILLISECONDS);
        return job;
    }

    private static void validateRequest(byte[] raw,String target) {
        String message=new String(raw,StandardCharsets.ISO_8859_1);
        int split=message.indexOf("\r\n\r\n");
        if(split<0) throw new IllegalArgumentException();
        String[] lines=message.substring(0,split).split("\r\n");
        String[] request=lines[0].split(" ");
        if(request.length!=3 || !Set.of("GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE").contains(request[0]) || !request[1].startsWith("/") || request[1].startsWith("//") || !Set.of("HTTP/1.0","HTTP/1.1").contains(request[2])) throw new IllegalArgumentException();
        int hosts=0,lengths=0,length=-1;
        for(int index=1; index<lines.length; index++) {
            int colon=lines[index].indexOf(':');
            if(colon<1) throw new IllegalArgumentException();
            String key=lines[index].substring(0,colon).toLowerCase(Locale.ROOT), value=lines[index].substring(colon+1).trim();
            if(!key.matches("[!#$%&'*+.^_`|~0-9a-z-]+") || value.indexOf('\r')>=0 || value.indexOf('\n')>=0) throw new IllegalArgumentException();
            if(key.equals("host")) { hosts++; if(!value.equals(target) && !value.equals(target+":80")) throw new IllegalArgumentException(); }
            if(key.equals("transfer-encoding") || key.equals("proxy-authorization")) throw new IllegalArgumentException();
            if(key.equals("content-length")) { lengths++; length=Integer.parseInt(value); }
        }
        int bodyLength=raw.length-split-4;
        if(hosts!=1 || lengths>1 || (lengths==1 && length!=bodyLength) || (lengths==0 && bodyLength!=0)) throw new IllegalArgumentException();
    }

    private synchronized void cancel(Job job) {
        if(!Set.of("queued","running","cancel_requested").contains(job.state)) return;
        job.cancelling=true;
        if(job.state.equals("queued") && job.task!=null && job.task.cancel(false)) job.state="cancelled";
        else { job.state="cancel_requested"; if(job.task!=null) job.task.cancel(true); }
        persistQuietly(job);
    }

    private synchronized String snapshot(Job job) {
        String response=job.response==null?"":Base64.getEncoder().encodeToString(job.response);
        return "{\"action_id\":\""+job.id+"\",\"state\":\""+job.state+"\",\"response_b64\":\""+response+"\"}";
    }

    private void persist(Job job) throws Exception {
        ledger.setProperty(job.id+".session",job.session); ledger.setProperty(job.id+".hash",job.hash); ledger.setProperty(job.id+".state",job.state);
        Files.createDirectories(path.toAbsolutePath().getParent());
        Path temporary=Files.createTempFile(path.toAbsolutePath().getParent(),"aria-replay-",".tmp");
        try {
            Files.setPosixFilePermissions(temporary,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            try(OutputStream output=Files.newOutputStream(temporary)) { ledger.store(output,"ARIA IDs and states only; no request/response credentials"); }
            Files.move(temporary,path,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
        } finally { Files.deleteIfExists(temporary); }
    }
    private void persistQuietly(Job job) { try { persist(job); } catch(Exception failure) { job.state="unknown"; } }
    public static Map<String,String> readForm(HttpExchange exchange) throws Exception {
        byte[] input=exchange.getRequestBody().readNBytes(110001);
        if(input.length>110000) throw new IllegalArgumentException();
        Map<String,String> result=new HashMap<>();
        for(String pair:new String(input,StandardCharsets.UTF_8).split("&")) {
            String[] parts=pair.split("=",2);
            if(parts.length==2) result.put(java.net.URLDecoder.decode(parts[0],StandardCharsets.UTF_8),java.net.URLDecoder.decode(parts[1],StandardCharsets.UTF_8));
        }
        return result;
    }
    private static void reply(HttpExchange exchange,String json) throws Exception {
        byte[] response=json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(200,response.length); exchange.getResponseBody().write(response);
    }
    @Override public void close() { synchronized(this) { for(Job job:jobs.values()) cancel(job); } workers.shutdownNow(); deadlines.shutdownNow(); }
}
