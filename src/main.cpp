#include "sha256.h"
#include <random>
#include <climits>

#include <iostream>


std::string randMessageGen(size_t len)
{
    auto engine = std::mt19937{std::random_device{}()};
    auto dist = std::uniform_real_distribution{};
    auto message = std::string(len, ' ');
    for(auto& ch : message)
        ch = static_cast<char>(std::numeric_limits<char>::max() * dist(engine));
    return message;
}

int main(int argc, char** argv)
{
    auto message = std::string("abc");

    auto hashObj = SHA256(message.c_str(), message.length());
    std::cout << hashObj.printOutputBits().get();
    return 0;
}