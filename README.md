# SecurePtr
Windows C++ Secured Pointer Template Class to encrypt/decrypt the DATA of std::string,std::wstring,CString or user defined classes/structs in memory

 ****WARNING***** This version does not take care of deep copying of class data.
*	 And adding a class will SecuredPtr does not mean it will call the contructor and when securedptr is destroyed , it will not call the destructor.
*    So any object inheritance is not properly maintained inside SecuredPtr.
*    Class objects can be recreated with the data recovered from SecuredPtr by calling construtors/destructors
*
*    Examples:
*    SecuredPtr<T> varaibles will keep the data of Type T in memory encrypted till its scope.
*    Like other smart pointers outside of the scope the SecuredPtr will destroy its internal data.
*
*    ***Accessing of member functions of member properties are allowed which is atomatically decrypt and encypt data in back-end****
*    SecuredPtr<CString> teststring  = CString("Hellohow");//Inside teststring the value is encrypted however all member accesses will work
*    teststring->MakeUpper(); // Call CString method
*    if(teststring == "HELLOHOW") //True
*
*    class struexmp {public :int a;string c;double d;}; // create a structure
*
*    SecuredPtr<struexmp> structexample2; // create structure variable
*    struexmp var{ 15,"hello",14.01 };
*    structexample2 = var; //Inside structexample2 value is encrypted however member accesses/changes are allowed
*    if(structexample2->c=="hello") // True
*
*    ***Dereferencing of value with unencrypted data using '*'(like pointers) from SecuredPtr***
*    SecuredPtr<std::wstring> hh;
*    hh= L"hello";
*    std::wstring h1 = *hh; //h1 value is normal string however hh keeps the encrypted value till its scope
*    
*    ****VI****
*    Please note as accessing member properties with '->' is costly as it decrypts and encrypts data on each access.
*    It is ok when there are not too many accesses. When too many accesses it is recommended to use '&' to improve perfomance.
*    However data inside SecuredPtr stays uncrypted till all the variables created by '&' goes out of scope.
*    If these vaiables are shared again and all is out of scope the SecuredPtr variable will re-encrypt the data automatically.
*
*    ***Get the pointer of unencrypted data using '&'(like pointers)***
*    SecuredPtr<struexmp> structexample2; //class struexmp {public :int a;string c;double d;};
*    struexmp var{ 15,"hello",14.01 };
*    structexample2 = var;
*    {                     //Create a scope
*       auto uncr = &var;  // structexample2 now have its internal data unecrypted
*       uncr->a = 17;      //Change the first member using the pointer variable
*    }                     //Going out of scope for uncr so uncr is destroyed now
*        //here structexample2 is encypted again
*    if(structexample2->a == 17) //True
*
*    Additionaly comparison operators, copy constructor work normally like other variables
*    ****Debug Value Display**** 
*    #define _ShowDebugVal to show decrypted data in SecuredPtr for debugging purpose
