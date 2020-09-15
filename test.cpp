// test.cpp : Defines the entry point for the console application.

//
https://gist.github.com/hasherezade/87158b926e33418f5d3b0a0026d0ccc2
https://coderoad.ru/3801517/%D0%9A%D0%B0%D0%BA-%D0%BF%D0%B5%D1%80%D0%B5%D1%87%D0%B8%D1%81%D0%BB%D0%B8%D1%82%D1%8C-%D0%BC%D0%BE%D0%B4%D1%83%D0%BB%D0%B8-%D0%B2-64-%D0%B1%D0%B8%D1%82%D0%BD%D0%BE%D0%BC-%D0%BF%D1%80%D0%BE%D1%86%D0%B5%D1%81%D1%81%D0%B5-%D0%B8%D0%B7-32-%D0%B1%D0%B8%D1%82%D0%BD%D0%BE%D0%B3%D0%BE-%D0%BF%D1%80%D0%BE%D1%86%D0%B5%D1%81%D1%81%D0%B0-WOW

#include "stdafx.h"
#include <cassert>
#include <vector>
#include <string>
#include <sstream>
#include <functional>
#include <dos.h>
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <stdlib.h>
#include <iostream>
#include <istream>
#include <ostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread/mutex.hpp>



const size_t MAX_BUFFER_SIZE = 8;



typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;



 struct split

 {

	 split(const std::string& str,char splitter):str_(str){

		 for (std::string each; std::getline(str_, each, splitter); particles.push_back(each));

	 }

	 

	 size_t count(void)

	 {

	    return (particles.size());

	 }



	 const std::string& get(size_t index_) const

	 {

		return ( particles[ index_ ] );

	 }

	 

	 ~split(){}

 private:

	 std::vector< std::string > particles;

	 std::istringstream str_;

 

 };





 struct list_files

 {

	 std::string

	 pwd(void)

	 {

		 char buffer_[MAX_PATH];

		 getcwd(buffer_,MAX_PATH-1);

		 curdir = buffer_;

		 return(curdir);

	 }



	 list_files(std::string pattern)

	 {

		file_ = _findfirst(pattern.c_str() , &fileinfo);

	//	if ( file_==0 ) 

  		   v_s.push_back(fileinfo.name);

		while(_findnext(file_, &fileinfo)==0)
		    v_s.push_back(std::string(fileinfo.name));

	}



	void to(std::vector<std::string>& out)

	{

	  out = v_s;

	}

 

 private:

	unsigned int file_;

	struct   _finddata_t fileinfo;

	std::vector<std::string> v_s;

    std::string curdir;



 };







 struct session

 {

  // boost::asio::streambuf response_;

   boost::mutex mutex;

   session(boost::asio::io_service& io_service):sock_(new boost::asio::ip::tcp::socket(io_service))

   {}



   socket_ptr socket()

   { 

	   return ( sock_ );

   }



  void 

  start()

  {

//	int x = 5;
//	if (std::cref(5).get() == std::cref(x).get())

//	  {printf("test! = %d \n\n",x);}
//
	  char temp_[]="Hello my dear friend...\r\n";
//
	  write_(temp_,sizeof(temp_));
//
	  read();
//
  }



  void 

  handle_write(const boost::system::error_code& error)

  {

    if (!error)

    {

		//printf("test!\n\n");

    }

  }



  void write_(char *data , size_t sz)

  {

    boost::asio::async_write(*sock_,

             boost::asio::buffer(data , sz),

             boost::bind(&session::handle_write, this,

             boost::asio::placeholders::error)

		   );

  

  

  }



  void write_(std::string  str)

  {

	  write_(str.c_str() , str.length());

  

  }





  void write_(const char *data , size_t sz)

  {

    char *data_ = new char[sz];

	memset(data_,0,sz);

	memcpy(data_,data,sz);

    boost::asio::async_write(*sock_,

             boost::asio::buffer(data_ , sz),

             boost::bind(&session::handle_write, this,

             boost::asio::placeholders::error)

		   );

  

  

  }


 void cmd(const split& cmd_)

 {
    std::string str = cmd_.get(0);
    if (str.find("dir") != std::string::npos)
	{
		std::string str_ = cmd_.get(1);
		str_.erase(std::remove(str_.begin(),str_.end(),'\n'));
		str_.erase(std::remove(str_.begin(),str_.end(),'\r'));

		std::vector<std::string> get;
		list_files lf(str_);
		lf.to(get);
		write_( std::string("directory:\r\n") );
		for (size_t i = 0; i < get.size() ;++i)
		{
			write_(get[i]);
			write_( std::string("\r\n") );
		}

		   __asm{nop}
	}

    if (str.find("cd") != std::string::npos)

	{
		   __asm{nop}
	   std::string dir_ = cmd_.get(1);
	   dir_.erase(std::remove(dir_.begin(),dir_.end(),'\r'));
	   dir_.erase(std::remove(dir_.begin(),dir_.end(),'\n'));
	
	   int err = chdir( dir_.c_str() );
	  if (!err)
	  {
		printf("change dir..\r\n");
		write_( std::string("change directory..\r\n") );
	  }

	}



    if (str.find("finish") != std::string::npos)

	{

		write_( std::string("goodbye!..\r\n") );

		exit(0);	

	}	
 }


 void read()

 {
	 boost::asio::async_read_until(*sock_, response_, "\n",
		    boost::bind(&session::handle_read_sl, this,
            boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
 }



  void 

 handle_read_sl(const boost::system::error_code& err,size_t length)

 {
	 auto data_ =  response_.data();
	 std::vector<char> buffer;
 	 std::string str_data = get_seq();
	 split sl(str_data,' ');
	 cmd(sl);
     boost::asio::async_read(*sock_, response_,
     boost::asio::transfer_at_least(1),
     boost::bind(&session::handle_read_content, this,
	 boost::asio::placeholders::error)
	 );

  

  }

 std::string get_seq()
 {

	std::string str_data;
	size_t sz = response_.data().size();
	std::vector<char> buffer;
	do
	{
	  char t_val = response_.sgetc();
	  if (0 != t_val)
	  {
	    str_data += t_val;
	    printf("%d," , t_val );
	  }
	}while (response_.snextc() != EOF);
	response_.commit(sz);
	return (str_data);
 }


 void handle_read_content(const boost::system::error_code& err)
  {    
	if (!err)
    {

		
		std::string str_data = get_seq();
  		split sl(str_data,' ');
		cmd(sl);
		
		boost::asio::async_read(*sock_, response_,
        boost::asio::transfer_at_least(1),
   	    boost::bind(&session::handle_read_content, this,
		boost::asio::placeholders::error));

		

	}
 }

  socket_ptr sock_;
  boost::asio::streambuf response_;

};



 



 struct server

 {



  server(boost::asio::io_service& io_service, short port) 

		 : io_service_(io_service),acceptor_(io_service, boost::asio::ip::tcp::endpoint

		 (boost::asio::ip::tcp::v4(), port))

 {
	new_session = new session(io_service_);
    acceptor_.async_accept(*new_session->socket(),
    boost::bind(&server::handle_accept, this,new_session->socket(), boost::placeholders::_1));
 }



 





 

 void 

 handle_accept(socket_ptr sock, const boost::system::error_code & err)

 {
	boost::system::error_code error;
	new_session->start();
 }

 private:

  boost::asio::io_service& io_service_;

  boost::asio::ip::tcp::acceptor acceptor_;

  session* new_session;

 };





 



int _tmain(int argc, _TCHAR* argv[])

{

  boost::asio::io_service service;

 // boost::asio::ip::tcp::endpoint ep( boost::asio::ip::tcp::v4(), 2001); // listen on 2001

 // boost::asio::ip::tcp::acceptor acc(service, ep);

  socket_ptr sock(new boost::asio::ip::tcp::socket(service));	

//	printf("test:%s\n",split_.get(0).c_str());

//		printf("test:%s\n",split_.get(1).c_str());



  server srv(service,2001);

	

	//  acc.async_accept(*sock,boost::bind( handle_accept, sock, boost::placeholders::_1) );

  service.run();

  return 0;

}



