#include <Windows.h>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <thread>
#include <cpprest/details/http_server.h>
#include <cpprest/json.h>

#pragma comment(lib, "cpprest_2_10.lib")

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

void handle_static_files(http_request request, const std::wstring& base_path)
{
    std::wstring file_path = base_path + request.relative_uri().path();
    std::ifstream file(file_path, std::ios::binary);
    if (file.is_open())
    {
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        std::string content_type;

        if (file_path.find(L".html") != std::wstring::npos)
            content_type = "text/html";
        else if (file_path.find(L".css") != std::wstring::npos)
            content_type = "text/css";
        else if (file_path.find(L".js") != std::wstring::npos)
            content_type = "application/javascript";
        else if (file_path.find(L".json") != std::wstring::npos)
            content_type = "application/json";
        else
            content_type = "application/octet-stream";

        request.reply(status_codes::OK, content, content_type);
    }
    else
    {
        request.reply(status_codes::NotFound, "File not found");
    }
}


void handle_api_requests(http_request request)
{

    if (request.relative_uri().path() == L"/yazidou" && request.method() == methods::GET) {
        
        json::value response_data;
        response_data[L"status"] = json::value::string(L"On the rockzzz");
        request.reply(status_codes::OK, response_data);
    
    } else if (request.relative_uri().path() == L"/test" && request.method() == methods::POST)
    {
        request.extract_json().then([request](json::value request_data) {
            std::wcout << L"Received JSON: " << request_data.serialize() << std::endl;

            json::value response_data;
            response_data[L"status"] = json::value::string(L"Data received successfully");
            response_data[L"received_data"] = request_data;

            return request.reply(status_codes::OK, response_data);
            }).wait();
    }

}

void start_web_server(const std::wstring& base_path)
{
    http_listener listener(L"http://localhost:8080");

    listener.support(methods::GET, [base_path](http_request request) {
        if (request.relative_uri().path() == L"/")
        {
            handle_static_files(request, base_path);
        }
        else
        {
            handle_static_files(request, base_path);
        }
        });

    try
    {
        listener.open().wait();
        std::wcout << L"Web server is listening on port 8080..." << std::endl;

        std::string line;
        std::getline(std::cin, line);

        listener.close().wait();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void start_api_server()
{
    http_listener listener(L"http://localhost:8090");

    listener.support(methods::GET, handle_api_requests);

    try
    {
        listener.open().wait();
        std::wcout << L"API server is listening on port 8090..." << std::endl;

        std::string line;
        std::getline(std::cin, line);

        listener.close().wait();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main()
{
    std::wstring base_path = L"C:/Users/1234Y/xacone.github.io/";

    std::thread web_server_thread(start_web_server, base_path);
    std::thread api_server_thread(start_api_server);

    web_server_thread.join();
    api_server_thread.join();

    return 0;
}
