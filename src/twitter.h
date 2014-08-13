#ifndef INCLUDE_GUARD_UUID_4B2317D2_322F_4620_BDFA_4FEBDA99E8CE
#define INCLUDE_GUARD_UUID_4B2317D2_322F_4620_BDFA_4FEBDA99E8CE

#include <ctime>

#include <string>
#include <memory>
#include <unordered_map>

#include <curlpp/Easy.hpp>

namespace Twitter {
    
    // RFC 3986 基づき URL エンコードを行う
    std::string UrlEncodeRfc3986(const std::string &url);
    
    // OAuth クラス
    class OAuth {
    
    // instance methods
    public:
        
        OAuth(
            const std::string &consumer_key        = "",
            const std::string &consumer_secret     = "",
            const std::string &access_token        = "",
            const std::string &access_token_secret = ""
            );
        
        // プロキシサーバーを設定
        void SetProxy(
            const std::string &proxy         = "",
            const std::string &proxy_userpwd = ""
            );
        
        // 認証 URL を取得する
        const std::string GetAuthorizeUrl();
        
        // PIN を設定する
        void SetOAuthVerifier(const std::string &oauth_verifier);
        
        // アクセストークンを取得する
        const std::string GetAccessToken(const std::string &oauth_verifier = "");
        
        // アクセストークンシークレットを取得
        const std::string GetAccessTokenSecret();
        
        // ユーザー ID を取得
        const std::string GetUserId();
        
        // スクリーンネームを取得
        const std::string GetScreenName();
    
    private:
        // リクエストトークンを取得
        const std::string GetRequestToken();
        
        // 署名を付与した　URL を取得する
        const std::string GetSignedUrl(
            const std::string &url,
            const std::string &query,
            const std::string &signature_key
            ) const;
        
        // リクエストトークンを取得する為の URL を取得
        const std::string GetRequestTokenUrl() const;
        
        // アクセストークンを取得する為の URL を取得
        const std::string GetAccessTokenUrl() const;
        
        // UNIX 時間を取得
        const std::time_t GetUnixTime() const;
        
        // ランダムな文字列を取得
        const std::string GetNonce() const;
        
        // HTTP クエリ文字列をパースする
        const std::unordered_map<std::string, std::string>
            ParseQueryString(const std::string &query) const;
        
        // リクエストを生成
        std::shared_ptr<cURLpp::Easy> GetRequest() const;
        
    // instance variable
    private:
        
        // プロキシの情報
        std::string proxy;
        std::string proxy_userpwd;
        
        // OAuth トークン
        std::string consumer_key;
        std::string consumer_secret;
        std::string request_token;
        std::string request_token_secret;
        std::string access_token;
        std::string access_token_secret;
        
        // URL
        std::string request_token_url;
        std::string access_token_url;
        std::string authorize_url;
        
        // Twitter ユーザー情報
        std::string user_id;
        std::string screen_name;
        
        // PIN
        std::string oauth_verifier;
    };
}

#endif