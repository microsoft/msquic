//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Linq;

namespace QuicTrace.DataModel
{
    public interface IQuicObject
    {
        ulong Id { get; }

        ulong Pointer { get; }

        uint ProcessId { get; }
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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods")]
        public QuicObjectKey(QuicEvent evt) : this(evt.PointerSize, evt.ObjectPointer, evt.ProcessId)
        {
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
        internal readonly Dictionary<QuicObjectKey, T> activeTable = new Dictionary<QuicObjectKey, T>();

        internal readonly List<T> inactiveList = new List<T>();

        public int Count => activeTable.Count + inactiveList.Count;

        private readonly ushort CreateEventId;

        private readonly ushort DestroyedEventId;

        private readonly Func<ulong, uint, T> ObjectConstructor;

        public QuicObjectSet(ushort createEventId, ushort destroyedEventId, Func<ulong, uint, T> constructor)
        {
            CreateEventId = createEventId;
            DestroyedEventId = destroyedEventId;
            ObjectConstructor = constructor;
        }

        public T? FindActive(QuicObjectKey key) => activeTable.TryGetValue(key, out var value) ? value : null;

        public T? RemoveActiveObject(QuicObjectKey key) => activeTable.Remove(key, out var value) ? value : null;

        public T? FindById(uint id)
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
                var old = RemoveActiveObject(key);
                if (old != null) inactiveList.Add(old);
                value = ObjectConstructor(key.Pointer, key.ProcessId);
                activeTable.Add(key, value);
            }
            else if (eventId == DestroyedEventId)
            {
                value = RemoveActiveObject(key);
                if (value != null) inactiveList.Add(value);
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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods")]
        public T FindOrCreateActive(QuicEvent evt) => FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));

        public void FinalizeObjects()
        {
            inactiveList.AddRange(activeTable.Select(it => it.Value));
            activeTable.Clear();
            inactiveList.Sort((a, b) => (int)(a.Id - b.Id));
        }

        public IReadOnlyList<T> GetObjects()
        {
            List<T> allObjects = new List<T>();
            allObjects.AddRange(inactiveList);
            allObjects.AddRange(activeTable.Select(it => it.Value));
            return allObjects;
        }
    }
}
