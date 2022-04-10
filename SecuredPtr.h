#pragma once
/*
/////////////////////////////////////////////////////////////////////////////
//
* @FILE: SecuredPtr.h : Secured Pointer Template Class
//
* @DESCRIPTION:
*   < Use this class to encrypt/decrypt the DATA of std::string,std::wstring,CString or user defined classes/structs in memory>
//
* [@TO_READ:
*    <
*    ****WARNING***** This version does not take care of deep copying of class data.
*	 And adding a class will SecuredPtr does not mean it will call the contructor and when securedptr is destroyed , it will not call the destructor.
*    So any object inheritance is not properly maintained inside SecuredPtr.
*    Class objects can be recreated with the data recovered from SecuredPtr by calling construtors/destructors
*
*    Examples:
*    SecuredPtr<T> varaibles will keep the data of Type T in memory encrypted till its scope.
*    Like other smart pointers outside of the scope the SecuredPtr will destroy its internal data.
*
*    //Accessing of member functions of member properties are allowed which is atomatically decrypt and encypt data in back-end
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
*    //Dereferencing of value with unencrypted data using '*'(like pointers) from SecuredPtr
*    SecuredPtr<std::wstring> hh;
*    hh= L"hello";
*    std::wstring h1 = *hh; //h1 value is normal string however hh keeps the encrypted value till its scope
*    
*    ****VI****
*    //Please note as accessing member properties with '->' is costly as it decrypts and encrypts data on each access.
*    //It is ok when there are not too many accesses. When too many accesses it is recommended to use '&' to improve perfomance.
*    //However data inside SecuredPtr stays uncrypted till all the variables created by '&' goes out of scope.
*    //If these vaiables are shared again and all is out of scope the SecuredPtr variable will re-encrypt the data automatically.
*
*    //Get the pointer of unencrypted data using '&'(like pointers)
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
*    #define _ShowDebugVal to show decrypted data in SecuredPtr for debugging purpose>]
//
* @VERS
//*******************************************************************-
//			|         |            |
// 	Version |  Date   | Author	   | comment about the modification
//*******************************************************************-
*   1.0     |03/07/22 | C.GHOSH   | Creation
//*******************************************************************-
/////////////////////////////////////////////////////////////////////////////
*/

#include "Windows.h"
#include "Wincrypt.h"
#include <string>
#include <memory>
#include <iostream>
#include <type_traits>
#include <mutex>
#include "atlstr.h"

#pragma comment(lib, "crypt32.lib")

using namespace std;

#ifdef _DEBUG
#define _ShowDebugVal
#else
#undef _ShowDebugVal
#endif

namespace Secured_Ptr
{

    template <typename T>
    class SecuredPtr
    {
    private:
        std::recursive_mutex m;
        size_t dataSize;
        PBYTE protectedData;
        bool isEncrypted = false;
        bool overwriteOnExit;
        weak_ptr<T> holder;
#ifdef _ShowDebugVal
        shared_ptr<T> debugval; //For debugging purpose seeing the real value and must be disabled for versions requiring encryption in memory
#endif
        void internalassign(const T *obj)
        {
            if (obj == nullptr)
            {
                return;
            }
            //if protectedData is already pointing to something,
            //securely overwrite and delete it
            if (protectedData)
            {
                SecureWipeData();
                free(protectedData);
            }

            //Re-format the data
            size_t mod;
            size_t dataBlockSize;

            //Get size of the object when not called from assign()
            PBYTE orgdata = nullptr;
            bool isFreeRequired = false;
            if (dataSize == 0)
            {
                GetSize<T>(*obj, dataSize);
                if (dataSize == 0)
                    return; // we do not anything if size cannot be calculated
                serialize<T>(*obj, &orgdata);
                isFreeRequired = true;
            }
            else
                orgdata = (PBYTE)obj; // if size is already provided then we do not do any calcuated size and treat as BYTE byffer

            //CryptProtectMemory requires data to be a multiple of its block size
            if (mod = dataSize % CRYPTPROTECTMEMORY_BLOCK_SIZE)
                dataBlockSize = dataSize + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod);
            else
                dataBlockSize = dataSize;

            protectedData = (PBYTE)malloc(dataBlockSize);
            memcpy(protectedData, orgdata, dataSize);
            if (isFreeRequired)
            {
                SecureZeroMemory(orgdata, _msize(orgdata));
                free(orgdata);
            }
        }

        //Serialize
        template<typename T>
        typename std::enable_if<std::is_same<T, CString>::value, void>::type* serialize(const T& str, PBYTE* out)
        {
            const std::size_t size = str.GetLength();
            if (size > 0)
            {
                *out = (PBYTE)malloc(size * sizeof(wchar_t));
                memcpy(*out, str.GetString(), size * sizeof(wchar_t));
            }
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<std::is_same<T, std::wstring>::value, void>::type*  serialize(const T& str, PBYTE* out)
        {
            const std::size_t size = str.length();
            if (size > 0)
            {
                *out = (PBYTE)malloc(size * sizeof(wchar_t));
                memcpy(*out, str.c_str(), size * sizeof(wchar_t));
            }
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<std::is_same<T, std::string>::value, void>::type* serialize(const T& str, PBYTE* out)
        {
            const std::size_t size = str.length();
            if (size > 0)
            {
                *out = (PBYTE)malloc(size * sizeof(char));
                memcpy(*out, str.c_str(), size * sizeof(char));
            }
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<(std::is_class<T>::value || std::is_fundamental<T>::value) && !(std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value), void>::type* serialize(const T& str, PBYTE* out)
        {
            const std::size_t size = sizeof(str);
            if (size > 0)
            {
                *out = (PBYTE)malloc(size);
                memcpy(*out, &str, size);
            }
            return nullptr;
        }

        //Deserialize
        template<typename T>
        typename std::enable_if<std::is_same<T, std::string>::value, void>::type* Deserialize(T* str)
        {
            new (str) T(reinterpret_cast<char*>(protectedData), dataSize / sizeof(char));
            return nullptr;
        }
        template<typename T>
        typename std::enable_if<std::is_same<T, std::wstring>::value || std::is_same<T, CString>::value, void>::type* Deserialize(T* str)
        {
            new (str) T(reinterpret_cast<wchar_t*>(protectedData), dataSize / sizeof(wchar_t));
            return nullptr;
        }

        //GetSize
        template<typename T>
        typename std::enable_if<std::is_same<T, CString>::value, void>::type* GetSize(const T& str, size_t& siz)
        {
            siz = str.GetLength() * sizeof(wchar_t);
            return nullptr;
        }
        template<typename T>
        typename std::enable_if<std::is_same<T, std::string>::value, void>::type* GetSize(const T& str, size_t& siz)
        {
            siz = str.length();
            return nullptr;
        }
        template<typename T>
        typename std::enable_if<std::is_same<T, std::wstring>::value, void>::type* GetSize(const T& str, size_t& siz)
        {
            siz = str.length() * sizeof(wchar_t);
            return nullptr;
        }
        template<typename T>
        typename std::enable_if< std::is_fundamental<T>::value, void>::type* GetSize(const T& str, size_t& siz)
        {
            siz = sizeof(str);
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<std::is_class<T>::value && !(std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value), void>::type* GetSize(const T& str, size_t& siz)
        {
            siz = sizeof(str);
            return nullptr;
        }

        //GetSharedPtr
        template<typename T>
        typename std::enable_if<std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value, void>::type* GetSharedPtr(shared_ptr<T>& nptr)
        {
            shared_ptr<T> temp(
                (T*)malloc(sizeof(T)), // Allocate CString,wstring etc
                [this](T *x) {
                    if (this->protectedData != nullptr)
                    {
                        std::lock_guard<std::recursive_mutex> lg(m);
                        dataSize = 0;
                        internalassign(x);// Though string are immutable but classes like CString can change their internal value so copy back that data
                        holder.reset();
                        ProtectMemory(true);
                    }
                    delete x; //call the destructor in case of string type objects
                });
            Deserialize<T>(temp.get());
            nptr = temp;   //TODO protected pointer could have been freed but count not as == operator will not work
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<(std::is_class<T>::value || std::is_fundamental<T>::value) && !(std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value), void>::type* GetSharedPtr(shared_ptr<T>& nptr)
        {
            shared_ptr<T> temp(
                reinterpret_cast<T*>(protectedData),
                [this](T *x) {
                    if (this->protectedData != nullptr)
                    {
                        std::lock_guard<std::recursive_mutex> lg(m);
                        holder.reset();
                        ProtectMemory(true); // Today change in data is not considered
                    }
                });
            nptr = temp;
            return nullptr;
        }


#ifdef _ShowDebugVal
        //GetSharedPtrDebug
        template<typename T>
        typename std::enable_if<std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value, void>::type* GetSharedPtrDebug()
        {
            if (protectedData != nullptr)
            {
                shared_ptr<T> temp(
                    (T*)malloc(sizeof(T)), // Allocate CString,wstring etc
                    [this](T *x) {
                        if (x != nullptr)
                        {
                            delete x; // call the destructor in case of string type objects
                            x = nullptr;
                        }

                    });
                Deserialize<T>(temp.get()); //Initiate the cons
                debugval.reset();
                debugval = temp;   //TODO protected pointer could have been freed but count not as == operator will not work
            }
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<(std::is_class<T>::value || std::is_fundamental<T>::value) && !(std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value), void>::type* GetSharedPtrDebug()
        {
            if (protectedData != nullptr)
            {
                //Create a copy of the data
                auto tempdata = (T*)malloc(dataSize);
                memcpy_s(tempdata, dataSize, protectedData, dataSize);
                shared_ptr<T> temp(
                    reinterpret_cast<T*>(tempdata),
                    [this](T *x) {
                        if (x != nullptr)
                        {
                            free(x);// Only free the memory dont call destructor as it is is not supported 
                            x = nullptr;
                        }
                    });
                debugval.reset();
                debugval = temp;
            }
            return nullptr;
        }
#endif // _ShowDebugVal

    public:

        //Constructor
        explicit SecuredPtr(bool wipeOnExit = true) noexcept
            : protectedData(nullptr), overwriteOnExit(wipeOnExit), dataSize(0) {
            holder.reset()/*, holder2.reset()*/;
        }
        explicit SecuredPtr(T *obj, bool wipeOnExit = true) noexcept
            : protectedData(nullptr), overwriteOnExit(wipeOnExit), dataSize(0)
        {
            if (obj != nullptr)
            {
                internalassign(const_cast<T*>(obj));
                ProtectMemory(true);
                delete obj;
            }
            holder.reset();
            // holder2.reset();
        }
        /*explicit SecuredPtr(const T *obj, bool wipeOnExit = true) noexcept
            : protectedData(nullptr), overwriteOnExit(wipeOnExit), reference(nullptr), dataSize(0)
        {
            if (obj != nullptr)
            {
                internalassign(const_cast<T*>(obj), false);
                ProtectMemory(true);
                this->reference = new RC();
                this->reference->AddRef();
            }
            holder.reset();
        }*/

        explicit SecuredPtr(const PBYTE obj, size_t size, bool IsSecured) // Does not clear the PBYTE but operator() clears the PBYTE 
            noexcept
            : protectedData(nullptr), dataSize(0)
        {
            if (obj == nullptr)
                return;
            size_t dataBlockSize;
            dataSize = size;
            if (IsSecured)
            {
                size_t mod;

                //CryptProtectMemory requires data to be a multiple of its block size
                if (mod = size % CRYPTPROTECTMEMORY_BLOCK_SIZE)
                    dataBlockSize = size + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod);
                else
                    dataBlockSize = size;
                //protectedptr must be null here as called from constructor
                protectedData = (PBYTE)malloc(dataBlockSize);
                memcpy(protectedData, obj, dataBlockSize);
                isEncrypted = true;
#ifdef _ShowDebugVal
                ProtectMemory(false);
                GetSharedPtrDebug<T>();
                ProtectMemory(true);
#endif
            }
            else
            {
                internalassign(reinterpret_cast<const T*>(obj));
                ProtectMemory(true);
            }
            SetWipeOnExit(true);
            holder.reset();
            // holder2.reset();
        }

        //Copy Constructor
        SecuredPtr(const SecuredPtr<T>& other) noexcept
            : protectedData(nullptr), dataSize(0)
        {
            this->swap(other);
        }

        //Copy Constructor
        SecuredPtr(const T& other) noexcept
            : protectedData(nullptr), dataSize(0)
        {
            internalassign(const_cast<T*>(&other));
            ProtectMemory(true);
            SetWipeOnExit(true);
            holder.reset();
            // holder2.reset();
        }

        //Destructor
        ~SecuredPtr()
        {
            if (protectedData != nullptr)
            {
                SecureWipeData();
                free(protectedData);
                protectedData = nullptr;
            }

            this->dataSize = 0;
            holder.reset();
            this->isEncrypted = false;
#ifdef _ShowDebugVal
            debugval.reset();
            /*            if (debugval != nullptr)
                        {
                            free(debugval);
                        }  */
#endif //_ShowDebugVal
        }
        void SetWipeOnExit(bool wipe) { overwriteOnExit = wipe; }
        bool IsProtected() const { return isEncrypted; }

        bool CanDecrypt()
        {
            if (isEncrypted)
            {
                //Test Decyption
                if (ProtectMemory(false))
                {
                    ProtectMemory(true);
                    return true;
                }
            }
            return false;
        }

        PBYTE GetProtectedBuffer()
        {
            PBYTE data = nullptr;
            if (isEncrypted)
            {
                //Give the whole buffer
                auto len = _msize(protectedData);
                data = (PBYTE)malloc(len);
                memcpy(data, protectedData, len);
            }
            return data;
        }

        size_t GetSize()
        {
            return dataSize;
        }

        //shared_ptr<BYTE[]> GetUnProtectedBuffer()
        //{
        //    if (holder2.expired())
        //    {
        //        ProtectMemory(false);
        //        shared_ptr<BYTE[]> shared_data(protectedData,
        //            [this](T* x)
        //            {
        //                if (this->protectedData != nullptr)
        //                {
        //                    std::lock_guard<std::recursive_mutex> lg(m);
        //                    holder2.reset();
        //                    ProtectMemory(true); // Today change in data is not considered
        //                }
        //            });
        //       // holder2 = shared_data;
        //    }
        //    return holder2.lock();
        //}

        bool ProtectMemory(bool encrypt)
        {
            if (protectedData == nullptr)
                return false;
            std::lock_guard<std::recursive_mutex> lg(m);
            size_t mod;
            size_t dataBlockSize;

            //CryptProtectMemory requires data to be a multiple of its block size
            if (mod = dataSize % CRYPTPROTECTMEMORY_BLOCK_SIZE)
                dataBlockSize = dataSize + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod);
            else
                dataBlockSize = dataSize;
#ifdef _ShowDebugVal
            if (!isEncrypted)
            {
                GetSharedPtrDebug<T>();
            }
#endif //_ShowDebugVal 

            if (encrypt && !isEncrypted)
            {
                isEncrypted = true;
                if (!CryptProtectMemory(protectedData, dataBlockSize,
                    CRYPTPROTECTMEMORY_SAME_PROCESS))
                {
                    return false;
                }
            }
            else if (!encrypt && isEncrypted)
            {
                isEncrypted = false;
                if (!CryptUnprotectMemory(protectedData, dataBlockSize,
                    CRYPTPROTECTMEMORY_SAME_PROCESS))
                {
                    return false;
                }
            }
            SecureZeroMemory(&mod, sizeof(mod));
            SecureZeroMemory(&dataBlockSize, sizeof(dataBlockSize));
            return true;
        }
        void SecureWipeData()
        {
            if (overwriteOnExit)
                SecureZeroMemory(protectedData, _msize(protectedData));
        }

        void swap(const SecuredPtr& other) noexcept
        {
            if (other.dataSize != 0)
            {
                size_t mod;
                size_t dataBlockSize;
                //CryptProtectMemory requires data to be a multiple of its block size
                if (mod = other.dataSize % CRYPTPROTECTMEMORY_BLOCK_SIZE)
                    dataBlockSize = other.dataSize + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod);
                else
                    dataBlockSize = other.dataSize;
                this->protectedData = (PBYTE)malloc(dataBlockSize);
                memcpy_s(this->protectedData, dataBlockSize, other.protectedData, dataBlockSize);
            }

            this->dataSize = other.dataSize;
            this->isEncrypted = other.isEncrypted;
            this->overwriteOnExit = other.overwriteOnExit;
            this->holder = other.holder;
#ifdef _ShowDebugVal
            ProtectMemory(false);
            GetSharedPtrDebug<T>();
            ProtectMemory(true);
#endif // _ShowDebugVal
        }

        T operator*()
        {
            return *(this->operator&());
        }

        shared_ptr<T> operator&()
        {
            shared_ptr<T> nptr{};
            if (holder.expired())
            {
                ProtectMemory(false);
                GetSharedPtr<T>(nptr);
                holder = nptr;
            }
            return holder.lock();
        }

        shared_ptr<T> operator->()
        {
            return this->operator&();
        }

        void operator()(PBYTE obj, size_t size, bool IsSecured)
        {
            SecuredPtr<T> temp(obj, size, IsSecured);
            *this = temp;
            SecureZeroMemory(obj, size);
            delete obj;
        }

        SecuredPtr& operator=(const SecuredPtr& rhs)
        {
            if (this != &rhs) // Avoid self assignment
            {
                this->~SecuredPtr(); // Can be called to clear existing files
                this->swap(rhs);
                return *this;
            }
        }

        SecuredPtr& operator=(const SecuredPtr&& rhs) noexcept
        {
            if (this != &rhs) // Avoid self assignment
            {
                this->~SecuredPtr();
                this->swap(rhs);
                return *this;
            }
        }

        SecuredPtr& operator=(const T& rhs)
        {
            this->~SecuredPtr();
            holder.reset();
            // holder2.reset();
            internalassign(const_cast<T*>(&rhs));
            if (protectedData != nullptr)
            {
                ProtectMemory(true);
            }
            SetWipeOnExit(true);
            return *this;
        }

        bool operator!=(const T& other)
        {
            return !(this->operator==(other));
        }

        bool operator==(const T& other)
        {
            ProtectMemory(false);
            volatile byte* thisData = protectedData;
            PBYTE otherData = nullptr;
            serialize<T>(other, &otherData);

            if (otherData == nullptr && this->empty())
                return true;

            if (otherData != nullptr && this->empty())
                return false;

            if (otherData == nullptr && !this->empty())
                return false;

            if (dataSize != _msize((void*)otherData))
            {
                ProtectMemory(true);
                free((void*)otherData);
                return false;
            }
            volatile byte result = 0;

            for (int i = 0; i < dataSize; i++)
            {
                result |= thisData[i] ^ otherData[i];
            }
            ProtectMemory(true);
            free((void*)otherData);
            return result == 0;
        }

        bool operator==(SecuredPtr& other)
        {
            if (dataSize != other.dataSize)
            {
                ProtectMemory(true);
                other.ProtectMemory(true);
                return false;
            }


            ProtectMemory(false);
            other.ProtectMemory(false);

            volatile byte* thisData = protectedData;
            volatile byte* otherData = other.protectedData;
            volatile byte result = 0;

            for (int i = 0; i < dataSize; i++)
            {
                result |= thisData[i] ^ otherData[i];
            }
            ProtectMemory(true);
            other.ProtectMemory(true);
            return result == 0;
        }
        bool operator!=(SecuredPtr& other)
        {
            return !(*this == other);
        }

        bool empty() const {
            if (this == nullptr)
                return true;
            return protectedData == nullptr;
        }
    };
}
