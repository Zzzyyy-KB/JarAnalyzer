package zju.cst.aces.dependencycheck.utils;
// 导入需要的类
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;

// 定义爬虫类
public class Crawler {

    // 定义要爬取的URL地址
    public static String URL = "";

    public Crawler(String url){
        this.URL = url;
    }
    public static ArrayList<String> Crawl() throws Exception {
        ArrayList<String> res =new ArrayList<>();
        // 创建一个HttpClient对象
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // 创建一个HttpGet对象，设置请求头
        HttpGet httpGet = new HttpGet(URL);
        httpGet.setHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36");
        // 执行请求，获取响应
        CloseableHttpResponse response = httpClient.execute(httpGet);
        // 判断响应状态是否为200
        if (response.getStatusLine().getStatusCode() == 200) {
            // 获取响应实体
            HttpEntity entity = response.getEntity();
            // 转换为字符串
            String xml = EntityUtils.toString(entity, "UTF-8");
            // 解析XML代码，获取Document对象
            Document document = Jsoup.parse(xml, "", org.jsoup.parser.Parser.xmlParser());
            // 通过选择器获取dependencies标签所在的元素
            Element dependenciesElement = document.select("dependencies").first();
            // 获取元素中的子元素（dependency标签）
            if(dependenciesElement==null)
                 return null;
            Elements dependencyElements = dependenciesElement.children();
            // 遍历每个dependency标签
            for (Element dependencyElement : dependencyElements) {
                // 获取groupId、artifactId、version、scope等属性的值
                String groupId = dependencyElement.select("groupId").text();
                String artifactId = dependencyElement.select("artifactId").text();
//                String version = dependencyElement.select("version").text();
//                String scope = dependencyElement.select("scope").text();
                // 打印结果
//                System.out.println(dependencyElement.text());
                res.add(groupId+":"+artifactId);


            }
        }
        // 关闭资源
        response.close();
        httpClient.close();
        return res;
    }

    public static void main(String[] args) {
        String str = "Ljava/util/jar/JarFile;Ljava/util/jar/JarEntry;Ljava/util/Set<Lorg/objectweb/asm/tree/ClassNode;>;)Ljava/util/Set<Lorg/objectweb/asm/tree/ClassNode;>;";
        String parts[]=str.split("[;<]");
        for (String part: parts
             ) {
            System.out.println(part);

        }
    }
}
