#include <ctime>
#include <cctype>

#include <iostream>
#include <string>
#include <memory>
#include <sstream>
#include <vector>
#include <unordered_map>

#include <clx/format.h>
#include <clx/sha1.h>
#include <clx/hmac.h>
#include <clx/hexdump.h>
#include <clx/salgorithm.h>
#include <clx/uri.h>
#include <clx/base64.h>

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>

#include "twitter.h"

namespace Twitter {
        
        // RFC 3986 基づき URL エンコードを行う
        std::string UrlEncodeRfc3986(const std::string &url){
                std::ostringstream encoded_url;
                
                for(std::size_t i = 0, l = url.size(); i < l; ++i){
                        const std::string exclude = "-._~"; // 除外文字
                        const char c              = url[i];
                        
                        // アルファベット、もしくは除外文字の場合
                        if(std::isalnum(c) || exclude.find(c) != std::string::npos){
                                encoded_url << c;
                        }
                        
                        else {
                                encoded_url << '%' << clx::format("%02X") % static_cast<int>(c);
                        }
                }
                
                return encoded_url.str();
        }
        
        OAuth::OAuth(
                const std::string &consumer_key,
                const std::string &consumer_secret,
                const std::string &access_token,
                const std::string &access_token_secret
                )
        {
                this->consumer_key        = consumer_key;
                this->consumer_secret     = consumer_secret;
                this->access_token        = access_token;
                this->access_token_secret = access_token_secret;
                
                this->request_token_url = "https://api.twitter.com/oauth/request_token";
                this->access_token_url  = "https://api.twitter.com/oauth/access_token";
                this->authorize_url     = "https://api.twitter.com/oauth/authorize";
        }
        
        // プロキシサーバーを設定
        void OAuth::SetProxy(
                const std::string &proxy,
                const std::string &proxy_userpwd
                )
        {
                this->proxy         = proxy;
                this->proxy_userpwd = proxy_userpwd;
        }
        
        // 認証 URL を取得する
        const std::string OAuth::GetAuthorizeUrl(){
                return this->authorize_url + "?oauth_token=" + this->GetRequestToken();
        }
        
        // PIN を設定する
        void OAuth::SetOAuthVerifier(const std::string &oauth_verifier){
                this->oauth_verifier = oauth_verifier;
        }
        
        // アクセストークンを取得する
        const std::string OAuth::GetAccessToken(const std::string &oauth_verifier){
                
                if(!oauth_verifier.empty()){
                        this->oauth_verifier = oauth_verifier;
                }
                
                // 取得されていない場合、新規に取得
                if(this->access_token.empty()){
                        
                        // アクセストークンを取得する為の URL
                        const std::string url = this->GetAccessTokenUrl();
                        
                        // レスポンス
                        std::ostringstream response;
                        
                        // リクエストを実行
                        {
                                const cURLpp::Cleanup cleaner;
                                const std::shared_ptr<cURLpp::Easy> request = this->GetRequest();
                                
                                request->setOpt(cURLpp::Options::Url(url));
                                request->setOpt(cURLpp::Options::WriteStream(&response));
                                request->perform();
                        }
                        
                        // 取得したデータを分解
                        std::unordered_map<std::string, std::string> queryMap
                                = this->ParseQueryString(response.str());
                        
                        this->access_token        = queryMap["oauth_token"];
                        this->access_token_secret = queryMap["oauth_token_secret"];
                        this->user_id             = queryMap["user_id"];
                        this->screen_name         = queryMap["screen_name"];
                }
                
                return this->access_token;
        }
        
        // アクセストークンシークレットを取得
        const std::string OAuth::GetAccessTokenSecret(){
                
                // 取得されていない場合、新規に取得
                if(this->access_token_secret.empty()){
                        this->GetAccessToken();
                }
                
                return this->access_token_secret;
        }
        
        // ユーザー ID を取得
        const std::string OAuth::GetUserId(){
                return this->user_id;
        }
        
        // スクリーンネームを取得
        const std::string OAuth::GetScreenName(){
                return this->screen_name;
        }
        
        // リクエストトークンを取得
        const std::string OAuth::GetRequestToken(){
                
                // リクエストトークンを取得する為の URL を取得
                const std::string url = this->GetRequestTokenUrl();
                
                // レスポンス
                std::ostringstream response;
                
                // リクエストを実行
                {
                        const cURLpp::Cleanup cleaner;
                        const std::shared_ptr<cURLpp::Easy> request = this->GetRequest();
                        
                        request->setOpt(cURLpp::Options::Url(url));
                        request->setOpt(cURLpp::Options::WriteStream(&response));
                        request->perform();
                }
                
                // 取得したデータを分解
                std::unordered_map<std::string, std::string> queryMap
                        = this->ParseQueryString(response.str());
                
                this->request_token        = queryMap["oauth_token"];
                this->request_token_secret = queryMap["oauth_token_secret"];
                
                return this->request_token;
        }
        
        // 署名を付与した　URL を取得する
        const std::string OAuth::GetSignedUrl(
                const std::string &url,
                const std::string &query,
                const std::string &signature_key
                ) const
        {
                // 署名するデータ
                std::string signature_data;
                
                signature_data += "GET&";
                signature_data += UrlEncodeRfc3986(url) + '&';
                signature_data += UrlEncodeRfc3986(query);
                
                // 署名する
                const clx::sha1 engine =
                        clx::hmac<clx::sha1>(
                                signature_key.c_str(),
                                signature_key.size(),
                                signature_data.c_str(),
                                signature_data.size()
                        );
                
                // 署名を取得
                const unsigned char *signature = engine.code();
                
                // 署名を追加したクエリ文字列
                std::ostringstream signed_query;
                
                signed_query << query;
                signed_query << "&oauth_signature=";
                signed_query << UrlEncodeRfc3986(clx::base64::encode(
                        reinterpret_cast<const char*>(signature), engine.size()));
                
                // URL を生成
                const std::string signed_url = url + '?' + signed_query.str();
                
                return signed_url;
        }
        
        // リクエストトークンを取得する為の URL を取得
    const std::string OAuth::GetRequestTokenUrl() const {
        
                // クエリ文字列
                std::ostringstream query;
                
                query << "oauth_consumer_key="     << consumer_key        << '&';
                query << "oauth_nonce="            << this->GetNonce()    << '&';
                query << "oauth_signature_method=" << "HMAC-SHA1"         << '&';
                query << "oauth_timestamp="        << this->GetUnixTime() << '&';
                query << "oauth_version="          << "1.0";
                
                // 署名するキー
                const std::string signature_key = this->consumer_secret + '&';
                
                return this->GetSignedUrl(this->request_token_url, query.str(), signature_key);
        }
        
        // アクセストークンを取得する為の URL を取得
        const std::string OAuth::GetAccessTokenUrl() const {
                
                // クエリ文字列
                std::ostringstream query;
                
                query << "oauth_consumer_key="     << consumer_key         << '&';
                query << "oauth_nonce="            << this->GetNonce()     << '&';
                query << "oauth_signature_method=" << "HMAC-SHA1"          << '&';
                query << "oauth_timestamp="        << this->GetUnixTime()  << '&';
                query << "oauth_token="            << this->request_token  << '&';
                query << "oauth_verifier="         << this->oauth_verifier << '&';
                query << "oauth_version="          << "1.0";
                
                // 署名するキー
                const std::string signature_key = consumer_secret + '&' + this->request_token_secret;
                
                return this->GetSignedUrl(this->access_token_url, query.str(), signature_key);
        }
        
        // UNIX 時間を取得
        const std::time_t OAuth::GetUnixTime() const {
                return std::time(0);
        }
        
        // ランダムな文字列を取得
        const std::string OAuth::GetNonce() const {
                return clx::hexdump(clx::str(clx::format("%s") % this->GetUnixTime()));
        }
        
        // HTTP クエリ文字列をパースする
        const std::unordered_map<std::string, std::string>
                OAuth::ParseQueryString(const std::string &query) const
        {
                // ハッシュテーブル
                std::unordered_map<std::string, std::string> params;
                
                // クエリ文字列をペアごとに分解した配列
                std::vector<std::string> pairs;
                
                // ペアごとに分解
                clx::split_if(query, pairs, clx::is_any_of("&"));
                
                // ハッシュテーブルへ変換
                for(std::size_t i = 0, l = pairs.size(); i < l; ++i){
                        const std::string &pair = pairs[i];
                        const std::size_t pos   = pair.find_first_of('=');
                        
                        // 形式が正しい場合、変換
                        if(pos != std::string::npos){
                                params[pair.substr(0, pos)] = clx::uri::decode(pair.substr(pos + 1));
                        }
                }
                
                return params;
        }
        
        // リクエストを生成
        std::shared_ptr<cURLpp::Easy> OAuth::GetRequest() const {
                std::shared_ptr<cURLpp::Easy> request(new cURLpp::Easy);
                
                // SSL 証明書検証を無効化
                request->setOpt(cURLpp::Options::SslVerifyPeer(false));
                
                // プロキシサーバーの設定がされている場合
                if(!this->proxy.empty()){
                        request->setOpt(cURLpp::Options::Proxy(this->proxy));
                        
                        if(!this->proxy_userpwd.empty()){
                                request->setOpt(cURLpp::Options::ProxyUserPwd(this->proxy_userpwd));
                        }
                }
                
                return request;
        }
}