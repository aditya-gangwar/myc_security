package in.myecash.security;

/**
 * Created by adgangwa on 28-02-2017.
 */
public class SecurityMisc {

    public static String getAutoAdminPasswd() {
        int i = 100+20+3;
        return "autoAdmin@"+String.valueOf(i);
    }
}
