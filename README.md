# SecurePtr
Windows C++ Secured Pointer Template Class to autpmatically encrypt/decrypt the DATA of std::string,std::wstring,CString or user defined classes/structs etc. in memory
by using inbuilt Windows DPAPI. However, it is possible to use the same concept  for other systems like Linux by changing the crypto implementation

 ***WARNING*** </BR>
     This version does not take care of deep copying of class data. </BR>
     Constructors and destructors are not called contructor and when securedptr is created/destroyed. </BR>
     Any object inheritance is not properly maintained inside SecuredPtr. </BR>
     Class objects can be recreated with the data recovered from SecuredPtr by calling construtors/destructors </BR>
   
***Examples:***
  SecuredPtr<T> varaibles will keep the data of Type T in memory encrypted till its scope.  </BR>
  Like other smart pointers outside of the scope the SecuredPtr will destroy its internal data. </BR>

***Accessing of member functions of member properties are allowed which is atomatically decrypt and encypt data in back-end***
  
  SecuredPtr< CString > teststring  = CString("Hellohow");//Inside teststring the value is encrypted however all member accesses will work </BR>
  teststring->MakeUpper(); // Call CString method </BR>
  if(teststring == "HELLOHOW") //True </BR>

  class struexmp {public :int a;string c;double d;}; // create a structure  </BR>
  
  struexmp var{ 15,"hello",14.01 };  </BR>
  SecuredPtr< struexmp > structexample2; // create structure variable  </BR>
  structexample2 = var; //Inside structexample2 value is encrypted however member accesses/changes are allowed  </BR>
  if(structexample2->c=="hello") // True  </BR>

***Dereferencing of value with unencrypted data using pointer operator from SecuredPtr***</BR>
  SecuredPtr< std::wstring > hh;  </BR>
  hh= L"hello";  </BR>
  std::wstring h1 = *hh; //h1 value is string with unencypted copy of data however hh keeps the copy of encrypted value till its scope  </BR>
  
****Very Important****
  Please note as accessing member properties with '->' is costly as it decrypts and encrypts data on each access.
  It is ok when there are not too many accesses. When too many accesses it is recommended to use '&' to improve perfomance.
  However data inside SecuredPtr stays uncrypted till all the variables created by '&' goes out of scope.
  If these vaiables are shared again and all is out of scope the SecuredPtr variable will re-encrypt the data automatically.

  ***Getting the pointer of unencrypted data using '&'(like pointers)***
  SecuredPtr< struexmp > structexample2; //class struexmp like above </BR>
  struexmp var{ 15,"hello",14.01 };  </BR>
  structexample2 = var;  </BR>
  {                      //Create a scope  </BR>
     auto uncr = &var;  // structexample2 now have its internal data unecrypted  </BR>
     uncr->a = 17;      //Change the first member using the pointer variable  </BR>
  }                     //Going out of scope for uncr so uncr is destroyed now  </BR>
  //here structexample2 is encypted again  </BR>
  if(structexample2->a == 17) //True  </BR>

  Additionaly comparison operators, copy constructor work normally like other variables  </BR>
***Debug Value Display***  </BR>
  #define _ShowDebugVal to show decrypted data in SecuredPtr for debugging purpose  </BR>
