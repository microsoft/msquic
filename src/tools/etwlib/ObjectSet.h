/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The ObjectSet class respresents a generic way to store objects that are
    represented by non-unique pointers. An object has a lifetime and after that,
    its pointer may be reused for a new object. An object is 'active' if it's
    currently using the pointer address; otherwise it's 'inactive' meaning it is
    no longer using that pointer (because it was freed).

--*/

#include <unordered_map>
#include <vector>
#include <stdint.h>

const uint32_t KernelProcessId = 4;

//
// A helper function to determine if a pointer refers to kernel memory. It does
// this by essentially checking if the high bit is TRUE.
//
inline bool IsKernelMemory(uint8_t PointerSize, uint64_t _Pointer) {
    if (PointerSize == 8) {
        return (int64_t)_Pointer < 0;
    } else { // PointerSize == 4
        return (int32_t)_Pointer < 0;
    }
}

//
// A helper struct to identify an object by it's pointer and process ID.
//
struct ObjectKey {
    uint64_t Pointer;
    uint32_t ProcessId;
    ObjectKey(uint8_t PointerSize, uint64_t _Pointer, uint32_t _ProcessId) {
        Pointer = _Pointer;
        //
        // Kernel objects are sometimes created on user threads. In that case
        // the object shouldn't be associated with the user process, but the
        // kernel process instead.
        //
        ProcessId = IsKernelMemory(PointerSize, _Pointer) ?
            KernelProcessId : _ProcessId;
    }
    bool operator==(const ObjectKey& Other) const {
        return Pointer == Other.Pointer && ProcessId == Other.ProcessId;
    }
};

namespace std {
template <>
struct hash<ObjectKey> {
    std::size_t operator()(const ObjectKey& k) const {
        return std::hash<uint64_t>()(k.Pointer) ^ std::hash<uint32_t>()(k.ProcessId);
    }
};
}

template<class T>
class ObjectSet {
public:

    std::unordered_map<ObjectKey,T*> ActiveTable;
    std::vector<T*> InactiveList;

    ObjectSet() { }

    ~ObjectSet() {
        for (auto it = ActiveTable.begin(); it != ActiveTable.end(); ++it) {
            delete it->second;
        }
        for (auto it = InactiveList.begin(); it != InactiveList.end(); ++it) {
            delete *it;
        }
    }

    size_t Size() const {
        return ActiveTable.size() + InactiveList.size();
    }

    T* FindActive(const ObjectKey& Key) const {
        auto it = ActiveTable.find(Key);
        if (it == ActiveTable.end()) {
            return nullptr;
        }
        return it->second;
    }

    T* RemoveActiveObject(const ObjectKey& Key) {
        auto it = ActiveTable.find(Key);
        if (it == ActiveTable.end()) {
            return nullptr;
        }
        auto Obj = it->second;
        InactiveList.push_back(Obj);
        ActiveTable.erase(it);
        return Obj;
    }

    T* FindById(uint32_t Id) const {
        for (auto it = ActiveTable.begin(); it != ActiveTable.end(); ++it) {
            if (it->second->Id == Id) {
                return it->second;
            }
        }
        for (auto it = InactiveList.begin(); it != InactiveList.end(); ++it) {
            if ((*it)->Id == Id) {
                return *it;
            }
        }
        return nullptr;
    }

    T* FindOrCreateActive(uint16_t EventId, const ObjectKey& Key) {
        T* Obj;
        if (EventId == T::CreatedEventId) {
            (void)RemoveActiveObject(Key);
            Obj = new T(Key.Pointer, Key.ProcessId);
            ActiveTable.emplace(Key, Obj);
        } else if (EventId == T::DestroyedEventId) {
            Obj = RemoveActiveObject(Key);
        } else {
            Obj = FindActive(Key);
        }

        if (!Obj) {
            Obj = new T(Key.Pointer, Key.ProcessId);
            ActiveTable.emplace(Key, Obj);
        }

        return Obj;
    }

    T* FindOrCreateActive(const ObjectKey& Key) {
        T* Obj = FindActive(Key);
        if (!Obj) {
            Obj = new T(Key.Pointer, Key.ProcessId);
            ActiveTable.emplace(Key, Obj);
        }
        return Obj;
    }

    static bool SortById(const T* A, const T* B) {
        return A->Id < B->Id;
    }

    void Finalize() {
        for (auto it = ActiveTable.begin(); it != ActiveTable.end(); ++it) {
            InactiveList.push_back(it->second);
        }
        ActiveTable.clear();
        ActiveTable.reserve(0);
        std::sort(InactiveList.begin(), InactiveList.end(), SortById);
    }

    template<class T2>
    void GetObjects(
        uint64_t BeginTimeStamp,
        uint64_t EndTimeStamp,
        std::vector<T2*> &AllObjects) const {
        for (auto it = InactiveList.begin(); it != InactiveList.end(); ++it) {
            if ((*it)->InitialTimeStamp <= EndTimeStamp &&
                (*it)->FinalTimeStamp >= BeginTimeStamp) {
                AllObjects.push_back(*it);
            }
        }
        for (auto it = ActiveTable.begin(); it != ActiveTable.end(); ++it) {
            if (it->second->InitialTimeStamp <= EndTimeStamp &&
                it->second->FinalTimeStamp >= BeginTimeStamp) {
                AllObjects.push_back(it->second);
            }
        }
    }
};
