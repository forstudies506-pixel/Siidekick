// Hindi for the findings view. Written by Claude; a native speaker should check it before the demo (#2).
// Titles name the check, not the failure, so they read right next to both ठीक and खामी.
// Tech words people already say in English (API key, server, route) stay in English.

export type Lang = "en" | "hi";

export const checkHi: Record<string, { title: string; why: string }> = {
  "secrets-in-repo": {
    title: "Repo में secrets",
    why: "Code में लिखी API key या password, repo देखने वाला कोई भी उठा सकता है। उसे .env में रखें, code में नहीं।",
  },
  "security-headers": {
    title: "Security headers",
    why: "ये headers browser को बताते हैं कि आपकी site को iframe में न खोले और बाहर की scripts पर भरोसा न करे। इनके बिना clickjacking जैसे हमले आसान होते हैं।",
  },
  "rate-limit": {
    title: "Login पर rate limit",
    why: "कोई bot एक मिनट में हज़ारों password आज़मा सकता है। Rate limit हर IP की कोशिशें सीमित करता है।",
  },
  "open-cors": {
    title: "CORS नियम",
    why: "CORS '*' होने पर कोई भी website आपकी API को user के browser से call कर सकती है। सिर्फ अपना domain allow करें।",
  },
  "auth-on-endpoints": {
    title: "Admin routes पर login",
    why: "/admin जैसा route बिना login के कोई भी खोल सकता है और data बदल सकता है।",
  },
  "sql-string-concat": {
    title: "SQL query कैसे बनी है",
    why: "User का input सीधे SQL में जोड़ने से SQL injection होता है: कोई पूरी table पढ़ या मिटा सकता है। '?' placeholder इस्तेमाल करें।",
  },
  "dependency-audit": {
    title: "Packages में known खामियाँ",
    why: "इस package के इस version में एक सार्वजनिक security खामी है। Fixed version पर update करें, फिर अपने tests चलाएँ।",
  },
  "input-validation": {
    title: "Route input की जाँच",
    why: "बिना जाँचे input से crash, गलत data या injection हो सकता है। हर route पर validate() लगाएँ।",
  },
  "firewall-rules": {
    title: "Firewall rules",
    why: "Server के सारे ports खुले हों तो database जैसी चीज़ें internet से दिख सकती हैं। सिर्फ 80 और 443 खोलें।",
  },
  "incident-playbook": {
    title: "Security incident की योजना",
    why: "Key leak हो या site hack हो, तब किसे बताना है और पहले क्या करना है, यह पहले से लिखा होना चाहिए।",
  },
  readme: {
    title: "README",
    why: "README के बिना नया teammate project चला नहीं पाता, और security की बातें छूट जाती हैं।",
  },
  "ci-workflow": {
    title: "CI workflow",
    why: "CI हर push पर tests चलाता है, ताकि टूटा code main तक न पहुँचे।",
  },
  "health-endpoint": {
    title: "Health endpoint",
    why: "/health से monitoring tool जान पाता है कि site चल रही है या बंद है।",
  },
  "error-handler": {
    title: "Error handler",
    why: "बिना error handler के crash होने पर user को stack trace दिख सकता है, जिसमें अंदर की जानकारी होती है।",
  },
  "payment-verification": {
    title: "Online payment की server पर जाँच",
    why: "अगर server, Razorpay का signature या Paytm/UPI का checksum जाँचे बिना payment मान लेता है, तो कोई भी नकली payment id भेजकर मुफ़्त pass या सामान ले सकता है।",
  },
  "indian-pii": {
    title: "Aadhaar, PAN और UPI data code और logs से बाहर",
    why: "Aadhaar, PAN, UPI id या जन्मतिथि code या logs में हो तो बहुत लोग उसे देख सकते हैं। पूरा नंबर कभी log न करें, सिर्फ़ आख़िरी 4 अंक।",
  },
  "otp-safety": {
    title: "OTP login में OTP गुप्त रहे",
    why: "OTP को API response में लौटाने या log करने से कोई भी किसी और के नंबर से login कर सकता है। OTP सिर्फ़ SMS से भेजें और crypto.randomInt से बनाएँ।",
  },
  "ui-heavy-animation": {
    title: "UI animation का भार",
    why: "बहुत भारी animation सस्ते phones पर page धीमा कर देता है। हल्का animation रखें या reduced-motion का ध्यान रखें।",
  },
  "hallucinated-package": {
    title: "Package सच में मौजूद है",
    why: "AI कभी-कभी ऐसे package का नाम लिख देता है जो registry पर है ही नहीं। Attacker उसी नाम से malware publish कर सकता है। Install से पहले नाम जाँचें।",
  },
  "client-exposed-secrets": {
    title: "Browser code में server key नहीं",
    why: "Frontend का code हर visitor पढ़ सकता है। Server की key वहाँ हो तो कोई भी उसे चुराकर आपके खर्चे पर चला सकता है। Key को backend में रखें।",
  },
  "baas-open-rules": {
    title: "Firebase और Supabase data बंद है",
    why: "Firebase/Supabase में browser सीधे database से बात करता है, rules ही अकेला ताला हैं। Rules खुले हों तो कोई भी data पढ़ या बदल सकता है।",
  },
  "jwt-misuse": {
    title: "Login token सही से जाँचा जाता है",
    why: "Token को verify किए बिना मानना, या code में लिखा secret, किसी को भी नकली login token बनाने देता है। verify() और env से secret इस्तेमाल करें।",
  },
};

export const ui = {
  en: {
    pass: "pass",
    fail: "fail",
    checksPass: "checks pass",
    of: "of",
    nothing: "Nothing to fix here.",
    reportOnly: "Reported only: this one needs the owner's own edit.",
    patchable: "A guarded patch can be proposed for this.",
  },
  hi: {
    pass: "ठीक",
    fail: "खामी",
    checksPass: "checks ठीक",
    of: "में से",
    why: "क्यों ज़रूरी है",
    nothing: "यहाँ कुछ ठीक करने को नहीं।",
    reportOnly: "सिर्फ रिपोर्ट: यह बदलाव owner को खुद करना होगा।",
    patchable: "इसके लिए guarded patch बन सकता है।",
  },
} as const;
