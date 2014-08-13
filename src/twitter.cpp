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
        
        // RFC 3986 ��Â� URL �G���R�[�h���s��
        std::string UrlEncodeRfc3986(const std::string &url){
                std::ostringstream encoded_url;
                
                for(std::size_t i = 0, l = url.size(); i < l; ++i){
                        const std::string exclude = "-._~"; // ���O����
                        const char c              = url[i];
                        
                        // �A���t�@�x�b�g�A�������͏��O�����̏ꍇ
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
        
        // �v���L�V�T�[�o�[��ݒ�
        void OAuth::SetProxy(
                const std::string &proxy,
                const std::string &proxy_userpwd
                )
        {
                this->proxy         = proxy;
                this->proxy_userpwd = proxy_userpwd;
        }
        
        // �F�� URL ���擾����
        const std::string OAuth::GetAuthorizeUrl(){
                return this->authorize_url + "?oauth_token=" + this->GetRequestToken();
        }
        
        // PIN ��ݒ肷��
        void OAuth::SetOAuthVerifier(const std::string &oauth_verifier){
                this->oauth_verifier = oauth_verifier;
        }
        
        // �A�N�Z�X�g�[�N�����擾����
        const std::string OAuth::GetAccessToken(const std::string &oauth_verifier){
                
                if(!oauth_verifier.empty()){
                        this->oauth_verifier = oauth_verifier;
                }
                
                // �擾����Ă��Ȃ��ꍇ�A�V�K�Ɏ擾
                if(this->access_token.empty()){
                        
                        // �A�N�Z�X�g�[�N�����擾����ׂ� URL
                        const std::string url = this->GetAccessTokenUrl();
                        
                        // ���X�|���X
                        std::ostringstream response;
                        
                        // ���N�G�X�g�����s
                        {
                                const cURLpp::Cleanup cleaner;
                                const std::shared_ptr<cURLpp::Easy> request = this->GetRequest();
                                
                                request->setOpt(cURLpp::Options::Url(url));
                                request->setOpt(cURLpp::Options::WriteStream(&response));
                                request->perform();
                        }
                        
                        // �擾�����f�[�^�𕪉�
                        std::unordered_map<std::string, std::string> queryMap
                                = this->ParseQueryString(response.str());
                        
                        this->access_token        = queryMap["oauth_token"];
                        this->access_token_secret = queryMap["oauth_token_secret"];
                        this->user_id             = queryMap["user_id"];
                        this->screen_name         = queryMap["screen_name"];
                }
                
                return this->access_token;
        }
        
        // �A�N�Z�X�g�[�N���V�[�N���b�g���擾
        const std::string OAuth::GetAccessTokenSecret(){
                
                // �擾����Ă��Ȃ��ꍇ�A�V�K�Ɏ擾
                if(this->access_token_secret.empty()){
                        this->GetAccessToken();
                }
                
                return this->access_token_secret;
        }
        
        // ���[�U�[ ID ���擾
        const std::string OAuth::GetUserId(){
                return this->user_id;
        }
        
        // �X�N���[���l�[�����擾
        const std::string OAuth::GetScreenName(){
                return this->screen_name;
        }
        
        // ���N�G�X�g�g�[�N�����擾
        const std::string OAuth::GetRequestToken(){
                
                // ���N�G�X�g�g�[�N�����擾����ׂ� URL ���擾
                const std::string url = this->GetRequestTokenUrl();
                
                // ���X�|���X
                std::ostringstream response;
                
                // ���N�G�X�g�����s
                {
                        const cURLpp::Cleanup cleaner;
                        const std::shared_ptr<cURLpp::Easy> request = this->GetRequest();
                        
                        request->setOpt(cURLpp::Options::Url(url));
                        request->setOpt(cURLpp::Options::WriteStream(&response));
                        request->perform();
                }
                
                // �擾�����f�[�^�𕪉�
                std::unordered_map<std::string, std::string> queryMap
                        = this->ParseQueryString(response.str());
                
                this->request_token        = queryMap["oauth_token"];
                this->request_token_secret = queryMap["oauth_token_secret"];
                
                return this->request_token;
        }
        
        // ������t�^�����@URL ���擾����
        const std::string OAuth::GetSignedUrl(
                const std::string &url,
                const std::string &query,
                const std::string &signature_key
                ) const
        {
                // ��������f�[�^
                std::string signature_data;
                
                signature_data += "GET&";
                signature_data += UrlEncodeRfc3986(url) + '&';
                signature_data += UrlEncodeRfc3986(query);
                
                // ��������
                const clx::sha1 engine =
                        clx::hmac<clx::sha1>(
                                signature_key.c_str(),
                                signature_key.size(),
                                signature_data.c_str(),
                                signature_data.size()
                        );
                
                // �������擾
                const unsigned char *signature = engine.code();
                
                // ������ǉ������N�G��������
                std::ostringstream signed_query;
                
                signed_query << query;
                signed_query << "&oauth_signature=";
                signed_query << UrlEncodeRfc3986(clx::base64::encode(
                        reinterpret_cast<const char*>(signature), engine.size()));
                
                // URL �𐶐�
                const std::string signed_url = url + '?' + signed_query.str();
                
                return signed_url;
        }
        
        // ���N�G�X�g�g�[�N�����擾����ׂ� URL ���擾
    const std::string OAuth::GetRequestTokenUrl() const {
        
                // �N�G��������
                std::ostringstream query;
                
                query << "oauth_consumer_key="     << consumer_key        << '&';
                query << "oauth_nonce="            << this->GetNonce()    << '&';
                query << "oauth_signature_method=" << "HMAC-SHA1"         << '&';
                query << "oauth_timestamp="        << this->GetUnixTime() << '&';
                query << "oauth_version="          << "1.0";
                
                // ��������L�[
                const std::string signature_key = this->consumer_secret + '&';
                
                return this->GetSignedUrl(this->request_token_url, query.str(), signature_key);
        }
        
        // �A�N�Z�X�g�[�N�����擾����ׂ� URL ���擾
        const std::string OAuth::GetAccessTokenUrl() const {
                
                // �N�G��������
                std::ostringstream query;
                
                query << "oauth_consumer_key="     << consumer_key         << '&';
                query << "oauth_nonce="            << this->GetNonce()     << '&';
                query << "oauth_signature_method=" << "HMAC-SHA1"          << '&';
                query << "oauth_timestamp="        << this->GetUnixTime()  << '&';
                query << "oauth_token="            << this->request_token  << '&';
                query << "oauth_verifier="         << this->oauth_verifier << '&';
                query << "oauth_version="          << "1.0";
                
                // ��������L�[
                const std::string signature_key = consumer_secret + '&' + this->request_token_secret;
                
                return this->GetSignedUrl(this->access_token_url, query.str(), signature_key);
        }
        
        // UNIX ���Ԃ��擾
        const std::time_t OAuth::GetUnixTime() const {
                return std::time(0);
        }
        
        // �����_���ȕ�������擾
        const std::string OAuth::GetNonce() const {
                return clx::hexdump(clx::str(clx::format("%s") % this->GetUnixTime()));
        }
        
        // HTTP �N�G����������p�[�X����
        const std::unordered_map<std::string, std::string>
                OAuth::ParseQueryString(const std::string &query) const
        {
                // �n�b�V���e�[�u��
                std::unordered_map<std::string, std::string> params;
                
                // �N�G����������y�A���Ƃɕ��������z��
                std::vector<std::string> pairs;
                
                // �y�A���Ƃɕ���
                clx::split_if(query, pairs, clx::is_any_of("&"));
                
                // �n�b�V���e�[�u���֕ϊ�
                for(std::size_t i = 0, l = pairs.size(); i < l; ++i){
                        const std::string &pair = pairs[i];
                        const std::size_t pos   = pair.find_first_of('=');
                        
                        // �`�����������ꍇ�A�ϊ�
                        if(pos != std::string::npos){
                                params[pair.substr(0, pos)] = clx::uri::decode(pair.substr(pos + 1));
                        }
                }
                
                return params;
        }
        
        // ���N�G�X�g�𐶐�
        std::shared_ptr<cURLpp::Easy> OAuth::GetRequest() const {
                std::shared_ptr<cURLpp::Easy> request(new cURLpp::Easy);
                
                // SSL �ؖ������؂𖳌���
                request->setOpt(cURLpp::Options::SslVerifyPeer(false));
                
                // �v���L�V�T�[�o�[�̐ݒ肪����Ă���ꍇ
                if(!this->proxy.empty()){
                        request->setOpt(cURLpp::Options::Proxy(this->proxy));
                        
                        if(!this->proxy_userpwd.empty()){
                                request->setOpt(cURLpp::Options::ProxyUserPwd(this->proxy_userpwd));
                        }
                }
                
                return request;
        }
}