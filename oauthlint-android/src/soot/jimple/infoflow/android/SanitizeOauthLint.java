package soot.jimple.infoflow.android;

import soot.*;
import soot.jimple.Stmt;
import soot.options.Options;
import soot.util.Chain;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class SanitizeOauthLint extends SceneTransformer {

    public static boolean checkMatchPatterns(String className, List<Pattern> patterns) {
        return patterns.stream().anyMatch(pattern -> pattern.matcher(className)
                .matches());
    }


    private boolean checkFacebookLoginClass(SootClass sootclass) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.facebook.AccessToken");
        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(sootclass.getName(), classPatterns);
    }

    private boolean checkGoogleLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.google.android.gms.auth.api.signin.GoogleSignInAccount");
        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkAmazonLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.amazon.identity.auth.device.authorization.AuthorizationActivity");
        classes.add("com.amazon.identity.auth.device.authorization.MAPAuthzDialog");
        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkTwitterLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("ncom.twitter.sdk.android.core.TwitterSessio");
        classes.add("com.twitter.sdk.android.core.identity.TwitterAuthClient");
        classes.add("twitter4j.auth.AccessToken");
        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkLinkedinLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.linkedin.android.mobilesdk.LISessionManager");
        classes.add("com.linkedin.android.mobilesdk.AccessToken");
        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkMicrosoftLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.microsoft.aad.adal.AuthenticationResult");
        classes.add("com.microsoft.aad.adal.AuthenticationCallback");
        classes.add("com.microsoft.aad.adal.AuthenticationContext");
        classes.add("com.microsoft.identity.client.AuthenticationResult");

        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkFoursquareLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.foursquare.android.nativeoauth.FoursquareOAuth");
        classes.add("com.foursquare.android.nativeoauth.model.AuthCodeResponse");
        classes.add("com.foursquare.android.nativeoauth.model.AccessTokenResponse");

        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkWeiboLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.sina.weibo.sdk.auth.Oauth2AccessToken");
        classes.add("com.sina.weibo.sdk.auth.AuthInfo");
        classes.add("com.sina.weibo.sdk.auth.WeiboAuthListener");
        classes.add("cn.sharesdk.sina.weibo.SinaWeibo");

        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkSnapchatLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.snapchat.kit.sdk.core.models.OAuth2Manager");

        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkVkontakteLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.vk.api.sdk.auth.VKAccessToken");
        classes.add("com.vk.api.sdk.auth.VKScope");
        classes.add("com.vk.api.sdk.VK");

        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }

    private boolean checkLineLoginClass(SootClass classname) {
        List<String> classes = new ArrayList<String>();
        classes.add("com.linecorp.linesdk.LineAccessToken");
        classes.add("com.linecorp.linesdk.auth.LineLoginResult");
        classes.add("com.linecorp.linesdk.auth.LineLoginApi");
        //add additional class names here

        List<Pattern> classPatterns = classes.stream().map(s -> Pattern.compile(s)).collect
                (Collectors.toList());

        return checkMatchPatterns(classname.getName(), classPatterns);
    }


    public void writeOutputs(String process_dir, List<String> sp_list) {
        String apkname = process_dir.substring(process_dir.lastIndexOf('/')+1);

        String[] sp_array = sp_list.stream().toArray(s -> new String[s]);
        String providers = String.join(",", sp_array);

        BufferedWriter out = null;
        try {
            FileWriter fstream = new FileWriter("out_communication.txt", true);
            out = new BufferedWriter(fstream);
            out.write(apkname+": "+ providers + "\n");
            out.close();
        } catch (IOException e) {
            System.err.println("Error in writting file: " + e.getMessage());
        }
    }

    public static List<String> getProcessedApks() {
        List<String> list = new ArrayList<>();
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(
                    "out_communication.txt"));
            String line = reader.readLine();
            while (line != null) {
                list.add(line.substring(0,line.indexOf(":")));
                // read next line
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return list;
    }

    public static void main(String[] args) {

        String app_dir = ".\\apps\\apks";
        File folder = new File(app_dir);
        for (File file: folder.listFiles()) {
            count++;
            G.reset();
            try{
                Options.v().set_src_prec(Options.src_prec_apk);
                Options.v().set_process_multiple_dex(true);
                Options.v().set_android_api_version(28);
                Options.v().set_output_format(Options.output_format_n);

                PackManager.v().getPack("wjtp")
                        .add(new Transform("wjtp.transformer", new SanitizeOauthLint()));
                soot.Main.v().run(
                        new String[] { "-W", "-allow-phantom-refs",
                                "-process-dir", app_dir+file.getName(),
                                "-android-jars", ".\\AppData\\Local\\Android\\Sdk\\platforms"
                        });

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }


//    @Override
//    protected void internalTransform(String phaseName, Map<String, String> options) {
//
//        Iterator<SootClass> queue = Scene.v().getApplicationClasses().iterator();
//        while(queue.hasNext()) {
//            SootClass sootclass = (SootClass) queue.next();
//
//            for(SootField sf: sootclass.getFields()) {
//                System.out.println("Field name"+sf.getName());
//            }
//            for (SootMethod sm : sootclass.getMethods()) {
//
//                if (!sm.isConcrete()) {
//                    continue;
//                }
//                Body body = sm.retrieveActiveBody();
//
//                Chain<Unit> units = body.getUnits();
//                Iterator<Unit> uit = units.snapshotIterator();
//
//                while (uit.hasNext()) {
//                    Stmt stmt = (Stmt) uit.next();
//                    if (stmt.toString().toLowerCase().contains("https://api.instagram.com/v1//users/self?access_token=")) {
//                        System.out.println("================================"+stmt.toString());
//                    }
//                    else if (stmt.toString().toLowerCase().contains("https://m.facebook.com/v2.8/dialog/apprequests?access_token=")) {
//                        System.out.println("================================"+stmt.toString());
//                    }
//                    else if (stmt.toString().toLowerCase().contains("consumer_secret")) {
//                        System.out.println("================================"+stmt.toString());
//                    }
//
//                }
//
//            }
//        }
//
//
//    }
}