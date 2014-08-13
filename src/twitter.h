#ifndef INCLUDE_GUARD_UUID_4B2317D2_322F_4620_BDFA_4FEBDA99E8CE
#define INCLUDE_GUARD_UUID_4B2317D2_322F_4620_BDFA_4FEBDA99E8CE

#include <ctime>

#include <string>
#include <memory>
#include <unordered_map>

#include <curlpp/Easy.hpp>

namespace Twitter {
    
    // RFC 3986 ��Â� URL �G���R�[�h���s��
    std::string UrlEncodeRfc3986(const std::string &url);
    
    // OAuth �N���X
    class OAuth {
    
    // instance methods
    public:
        
        OAuth(
            const std::string &consumer_key        = "",
            const std::string &consumer_secret     = "",
            const std::string &access_token        = "",
            const std::string &access_token_secret = ""
            );
        
        // �v���L�V�T�[�o�[��ݒ�
        void SetProxy(
            const std::string &proxy         = "",
            const std::string &proxy_userpwd = ""
            );
        
        // �F�� URL ���擾����
        const std::string GetAuthorizeUrl();
        
        // PIN ��ݒ肷��
        void SetOAuthVerifier(const std::string &oauth_verifier);
        
        // �A�N�Z�X�g�[�N�����擾����
        const std::string GetAccessToken(const std::string &oauth_verifier = "");
        
        // �A�N�Z�X�g�[�N���V�[�N���b�g���擾
        const std::string GetAccessTokenSecret();
        
        // ���[�U�[ ID ���擾
        const std::string GetUserId();
        
        // �X�N���[���l�[�����擾
        const std::string GetScreenName();
    
    private:
        // ���N�G�X�g�g�[�N�����擾
        const std::string GetRequestToken();
        
        // ������t�^�����@URL ���擾����
        const std::string GetSignedUrl(
            const std::string &url,
            const std::string &query,
            const std::string &signature_key
            ) const;
        
        // ���N�G�X�g�g�[�N�����擾����ׂ� URL ���擾
        const std::string GetRequestTokenUrl() const;
        
        // �A�N�Z�X�g�[�N�����擾����ׂ� URL ���擾
        const std::string GetAccessTokenUrl() const;
        
        // UNIX ���Ԃ��擾
        const std::time_t GetUnixTime() const;
        
        // �����_���ȕ�������擾
        const std::string GetNonce() const;
        
        // HTTP �N�G����������p�[�X����
        const std::unordered_map<std::string, std::string>
            ParseQueryString(const std::string &query) const;
        
        // ���N�G�X�g�𐶐�
        std::shared_ptr<cURLpp::Easy> GetRequest() const;
        
    // instance variable
    private:
        
        // �v���L�V�̏��
        std::string proxy;
        std::string proxy_userpwd;
        
        // OAuth �g�[�N��
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
        
        // Twitter ���[�U�[���
        std::string user_id;
        std::string screen_name;
        
        // PIN
        std::string oauth_verifier;
    };
}

#endif