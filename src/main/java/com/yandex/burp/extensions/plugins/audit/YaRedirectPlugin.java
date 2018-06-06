package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.Utils;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by a-abakumov on 26/05/2017.
 */
public class YaRedirectPlugin implements IAuditPlugin {

    private static final ArrayList<String> Payloads = new ArrayList<>();

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private final int ISSUE_TYPE = 0x080a000e;
    private final String ISSUE_NAME = "Yandex Open Redirect Issue";
    private final String SEVERITY = "Medium";
    private final String CONFIDENCE = "Certain";


    private final List<String> REDIRECTS = Arrays.asList("//EXAMPLE.COM", "/\\EXAMPLE.COM", "\\/EXAMPLE.COM",
            "HTTPS://EXAMPLE.COM", "HTTP://EXAMPLE.COM",
            // Internet Explorer
            "/\t/EXAMPLE.COM", "\\\t\\EXAMPLE.COM",
            // Chrome
            "///EXAMPLE.COM", "\\/\\EXAMPLE.COM", "/\\/EXAMPLE.COM",
            "/%5cEXAMPLE.COM", "/https://%5cEXAMPLE.COM", "/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/", "http://0xd8.0x3a.0xd6.0xce",
            "http://XY>.7d8T\205pZM@0xd83ad6ce", "http://472.314.470.462", "http://[::216.58.214.206]", "http://3H6k7lIAiqjfNeN@[::216.58.214.206]",
            "/ゝEXAMPLE.COM", "〵EXAMPLE.COM", "%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d", "\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)",
            "\152\141\166\141\163\143\162\151\160\164\072alert(1)", "http://;@EXAMPLE.COM");

    public YaRedirectPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_URL) return null;

        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = baseRequestResponse.getHttpService();

        for (String payload : Payloads) {
            IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService,
                    insertionPoint.buildRequest(this.helpers.stringToBytes(payload)));
            IScanIssue res = analyzeResponse(attack);
            if (res != null) issues.add(res);
        }
        if (issues.size() > 0) return issues;

        return issues;
    }

    public IScanIssue analyzeResponse(IHttpRequestResponse requestResponse) {
        IResponseInfo resp = helpers.analyzeResponse(requestResponse.getResponse());
        if (resp == null || resp.getStatusCode() < 300 || resp.getStatusCode() >= 400) return null;
        List<String> headers = resp.getHeaders();

        String locationHeader = Utils.getHeaderValue(headers, "Location");
        if (locationHeader == null) return null;
        for (String redirect : REDIRECTS) {
            if (locationHeader.toUpperCase().startsWith(redirect)) {
                String attackDetails = "Open redirect vulnerability was found at: <b>" +
                        helpers.analyzeRequest(requestResponse).getUrl().toString() + "</b>\n";
                List responseMarkers = new ArrayList(1);
                responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf("LOCATION"),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf("LOCATION") + "LOCATION".length()});

                return new CustomScanIssue(requestResponse.getHttpService(),
                        this.helpers.analyzeRequest(requestResponse).getUrl(),
                        new IHttpRequestResponse[]{this.callbacks.applyMarkers(requestResponse, null, responseMarkers)},
                        attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                        "", "", "");
            }
        }
        return null;
    }
}
