#include <iostream>
#include <string>

#include "twitter.h"

int main(int argc, char **argv){
    const std::string consumer_key    = "Consumer Key";
    const std::string consumer_secret = "Consumer Secret";
    
    Twitter::OAuth oauth(consumer_key, consumer_secret);
    
#if 0
    // use proxy
    oauth.SetProxy("proxy.example.com:8080");
#endif
    
    std::cout << "Authorize URL:"        << std::endl;
    std::cout << oauth.GetAuthorizeUrl() << std::endl << std::endl;
    
    std::string oauth_verifier;
    
    std::cout << "PIN:" << std::endl;
    std::cin  >> oauth_verifier;
    std::cout << std::endl;
    
    std::cout << "Access Token:"                      << std::endl;
    std::cout << oauth.GetAccessToken(oauth_verifier) << std::endl << std::endl;
    
    std::cout << "Access Token Secret:"       << std::endl;
    std::cout << oauth.GetAccessTokenSecret() << std::endl << std::endl;
    
    std::cout << "User ID:"        << std::endl;
    std::cout << oauth.GetUserId() << std::endl << std::endl;
    
    std::cout << "Screen Name:"        << std::endl;
    std::cout << oauth.GetScreenName() << std::endl;
    
    return 0;
}