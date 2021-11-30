package soot.jimple.infoflow.android.source;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CheckSecret {
    public static String consumer_secret = "kWWQfMu9zZ5UTPxRXHsG6418wY1KLPvUuGPbMoe5g&";
    static String stmt = "<com.example.myapplication.MainActivity: java.lang.String consumer_secret> = \"kWWQfMu9zZ5UTPxRXHsG6418wY1KLPvUuGPbMoe5g\";";

    public static void main(String[] args) {
        String regex = "^[a-zA-Z0-9]+$";

        Pattern pattern = Pattern.compile(regex);

        String secret = stmt.substring(stmt.lastIndexOf("="));
        secret = secret.substring(secret.indexOf("\"")+1,secret.lastIndexOf("\"")-1);
        System.out.println(secret);

        Matcher matcher = pattern.matcher(secret);
        System.out.println(matcher.matches());

    }
}
