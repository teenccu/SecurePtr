#pragma once

//*******************************************************************-
//		|         |            	|
// 	Version |  Date   | Author	| comment about the modification
//*******************************************************************-
*   	1.0     |03/07/22 | C.GHOSH  	 | Creation
//*******************************************************************-
/////////////////////////////////////////////////////////////////////////////

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
        void internalassign(const T* obj)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
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
                if (orgdata != nullptr)	// KW fix - @AE 04/10/2022
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
            if (protectedData != nullptr && orgdata != nullptr)	// KW fix - @AE 04/10/2022
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
                if (*out != nullptr)										// KW fix - @AE 04/10/2022
                    memcpy(*out, str.GetString(), size * sizeof(wchar_t));
            }
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<std::is_same<T, std::wstring>::value, void>::type* serialize(const T& str, PBYTE* out)
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
                [this](T* x) {
                    if (this->protectedData != nullptr)
                    {
                        std::lock_guard<std::recursive_mutex> lg(m);
                        //if protectedData is already pointing to something,
                        //securely overwrite and delete it
                        if (protectedData)
                        {
                            SecureWipeData();
                            free(protectedData);
                            protectedData = nullptr;
                        }
                        dataSize = 0;
                        internalassign(x);// Though string are immutable but classes like CString can change their internal value so copy back that data
                        holder.reset();
                        ProtectMemory(true);
                    }
            delete x; //call the destructor in case of string type objects
                });
            if (temp != nullptr)	// KW fix - @AE 04/10/2022
                Deserialize<T>(temp.get());
            nptr = temp;   //TODO protected pointer could have been freed but count not as == operator will not work
            return nullptr;
        }

        template<typename T>
        typename std::enable_if<(std::is_class<T>::value || std::is_fundamental<T>::value) && !(std::is_same<T, std::wstring>::value || std::is_same<T, std::string>::value || std::is_same<T, CString>::value), void>::type* GetSharedPtr(shared_ptr<T>& nptr)
        {
            shared_ptr<T> temp(
                reinterpret_cast<T*>(protectedData),
                [this](T* x) {
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
                    [this](T* x) {
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
                    [this](T* x) {
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
        explicit SecuredPtr(T* obj, bool wipeOnExit = true) noexcept
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
            : protectedData(nullptr), dataSize(0), overwriteOnExit(true)
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
                if (protectedData != nullptr)		// KW fix - @AE 04/10/2022
                {
                    memcpy(protectedData, obj, dataBlockSize);
                    isEncrypted = true;
                }
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
        void ClearData()
        {
            std::lock_guard<std::recursive_mutex> lg(m);
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
        //Destructor
        ~SecuredPtr()
        {
            ClearData();
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
                if (data != nullptr)	// KW fix - @AE 04/10/2022
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
            if (overwriteOnExit && protectedData != nullptr && dataSize > 0)
                SecureZeroMemory(protectedData, dataSize);
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
                if (this->protectedData != nullptr)
                    free(protectedData);
                this->protectedData = (PBYTE)malloc(dataBlockSize);
                if (this->protectedData != nullptr)	// KW fix - @AE 04/10/2022
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
            std::lock_guard<std::recursive_mutex> lg(m);
            return *(this->operator&());
        }

        shared_ptr<T> operator&()
        {
            std::lock_guard<std::recursive_mutex> lg(m);
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
            std::lock_guard<std::recursive_mutex> lg(m);
            return this->operator&();
        }

        void operator()(PBYTE obj, size_t size, bool IsSecured)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
            SecuredPtr<T> temp(obj, size, IsSecured);
            *this = temp;
            SecureZeroMemory(obj, size);
            delete obj;
        }

        SecuredPtr& operator=(const SecuredPtr& rhs)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
            if (this != &rhs) // Avoid self assignment
            {
                ClearData(); // Can be called to clear existing files
                this->swap(rhs);
                return *this;
            }
        }

        SecuredPtr& operator=(const SecuredPtr&& rhs) noexcept
        {
            std::lock_guard<std::recursive_mutex> lg(m);
            if (this != &rhs) // Avoid self assignment
            {
                ClearData();
                this->swap(rhs);
                return *this;
            }
        }

        SecuredPtr& operator=(const T& rhs)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
            ClearData();
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

        //constant time comparison 
        bool operator!=(const T& other)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
            return !(this->operator==(other));
        }

        //constant time comparison 
        bool operator==(const T& other)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
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
                if (result == 1)
                    break;
            }
            ProtectMemory(true);
            free((void*)otherData);
            return result == 0;
        }


        //constant time comparison 
        bool operator==(SecuredPtr& other)
        {
            std::lock_guard<std::recursive_mutex> lg(m);
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
            std::lock_guard<std::recursive_mutex> lg(m);
            return !(*this == other);
        }

        bool empty() const {
            if (this == nullptr)
                return true;
            return protectedData == nullptr;
        }
    };
}
