﻿//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Performance.SDK;

namespace MsQuicTracing.DataModel
{
    public interface IQuicObject
    {
        ulong Pointer { get; }

        uint ProcessId { get; }

        ulong Id { get; }

        Timestamp InitialTimeStamp { get; }

        Timestamp FinalTimeStamp { get; }
    }

    public readonly struct QuicObjectKey : IEquatable<QuicObjectKey>
    {
        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public static bool IsKernelMemory(int pointerSize, ulong pointer)
        {
            if (pointerSize == 8)
            {
                return (long)pointer < 0;
            }
            else
            {
                return (int)pointer < 0;
            }
        }

        public QuicObjectKey(int pointerSize, ulong pointer, uint processId)
        {
            Pointer = pointer;
            ProcessId = IsKernelMemory(pointerSize, pointer) ? 4 : processId;
        }

        public override bool Equals(object? obj)
        {
            return obj is QuicObjectKey key && Equals(key);
        }

        public bool Equals(QuicObjectKey other)
        {
            return Pointer == other.Pointer &&
                   ProcessId == other.ProcessId;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Pointer, ProcessId);
        }

        public static bool operator ==(QuicObjectKey left, QuicObjectKey right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(QuicObjectKey left, QuicObjectKey right)
        {
            return !(left == right);
        }
    }

    public sealed class QuicObjectSet<T> where T : class, IQuicObject
    {
        private Dictionary<QuicObjectKey, T> activeTable = new Dictionary<QuicObjectKey, T>();

        private List<T> inactiveList = new List<T>();

        public int Count => activeTable.Count + inactiveList.Count;

        private ushort CreateEventId;

        private ushort DestroyedEventId;

        private Func<ulong, uint, T> ObjectConstructor;

        public QuicObjectSet(ushort createEventId, ushort destroyedEventId, Func<ulong, uint, T> constructor)
        {
            CreateEventId = createEventId;
            DestroyedEventId = destroyedEventId;
            ObjectConstructor = constructor;
        }

        public T? FindActive(QuicObjectKey key) => activeTable.TryGetValue(key, out var value) ? value : null;

        public T? RemoveActiveObject(QuicObjectKey key) => activeTable.Remove(key, out var value) ? value : null;

        public T? FindById(UInt32 id)
        {
            T? value = activeTable.Where(it => it.Value.Id == id).Select(it => it.Value).FirstOrDefault();
            if (value is null)
            {
                value = inactiveList.Where(it => it.Id == id).FirstOrDefault();
            }
            return value;
        }

        public T FindOrCreateActive(ushort eventId, QuicObjectKey key)
        {
            T? value;
            if (eventId == CreateEventId)
            {
                RemoveActiveObject(key);
                value = ObjectConstructor(key.Pointer, key.ProcessId);
                activeTable.Add(key, value);
            }
            else if (eventId == DestroyedEventId)
            {
                value = RemoveActiveObject(key);
            }
            else
            {
                value = FindActive(key);
            }

            if (value is null)
            {
                value = ObjectConstructor(key.Pointer, key.ProcessId);
                activeTable.Add(key, value);
            }

            return value;
        }

        public T FindOrCreateActive(QuicObjectKey key)
        {
            T? value = FindActive(key);
            if (value is null)
            {
                value = ObjectConstructor(key.Pointer, key.ProcessId);
                activeTable.Add(key, value);
            }
            return value;
        }

        public void FinalizeObjects()
        {
            inactiveList.AddRange(activeTable.Select(it => it.Value));
            activeTable.Clear();
            inactiveList.Sort((a, b) => (int)(a.Id - b.Id));
        }

        public List<T> GetObjects()
        {
            List<T> allObjects = new List<T>();
            allObjects.AddRange(inactiveList);
            allObjects.AddRange(activeTable.Select(it => it.Value));
            return allObjects;
        }
    }
}
