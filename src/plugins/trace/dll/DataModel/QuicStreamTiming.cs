//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public enum QuicStreamState
    {
        Alloc,
        QueueSend,
        ProcessSend,
        Frame,
        Write,
        WriteOther,
        Encrypt,
        Send,
        IdleSent,
        QueueRecv,
        ProcessRecv,
        Decrypt,
        Read,
        ReadOther,
        AppRecv,
        ProcessAppRecv,
        IdleRecv,
        IdleBoth,
        CleanUp
    };

    public sealed class QuicStreamTiming
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>")]
        public static QuicStreamState[] States => (QuicStreamState[])Enum.GetValues(typeof(QuicStreamState));

        //
        // Indicates if this timings has been completed.
        //
        public bool IsFinalized { get; internal set; }

        //
        // Indicates if this timings is for the client or server side.
        //
        public bool IsServer { get; internal set; }

        //
        // The stream has been allocated
        //
        public bool IsAllocated { get; internal set; }

        //
        // The application is actively handling a receive.
        //
        public bool InAppRecv { get; internal set; }

        //
        // Time of StreamAppReceiveCompleteCall event being emitted.
        //
        public Timestamp AppRecvCompletion { get; internal set; }

        //
        // The send direction of the stream has been shutdown.
        //
        public bool SendShutdown { get; internal set; }

        //
        // The receive direction of the stream has been shutdown.
        //
        public bool RecvShutdown { get; internal set; }

        //
        // Indicates if an error or unexpected state occurred while processing this request.
        //
        public bool EncounteredError { get; internal set; }

        //
        // The current state of the request.
        //
        public QuicStreamState State { get; set; } = QuicStreamState.Alloc;

        //
        // The first time State was updated.
        //
        public Timestamp InitialStateTime { get; internal set; }

        //
        // The last time State was updated.
        //
        public Timestamp LastStateChangeTime { get; internal set; }

        //
        // Time of the first packet being received.
        //
        public Timestamp FirstPacketRecv { get; internal set; }

        //
        // Time of the first packet being sent.
        //
        public Timestamp FirstPacketSend { get; internal set; }

        //
        // Currently processing send packet.
        //
        internal QuicSendPacket? SendPacket;

        //
        // Currently processing receive packet.
        //
        internal QuicReceivePacket? RecvPacket;

        //
        // The time spent in each RequestState (in nanoseconds).
        //
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "<Pending>")]
        public ulong[] Times = new ulong[States.Length];

        //
        // Returns time spent in microseconds
        //
        public IEnumerable<double> TimesUs { get { return Times.Select(t => t / 1000.0); } }

        //
        // Set of all the individual state changes.
        //
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "<Pending>")]
        public List<(QuicStreamState, Timestamp)> StateChanges = new List<(QuicStreamState, Timestamp)>();

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>")]
        public (QuicStreamState, Timestamp, TimestampDelta)[] StateChangeDeltas
        {
            get
            {
                var previousTime = InitialStateTime;
                var states = new List<(QuicStreamState, Timestamp, TimestampDelta)>(StateChanges.Count);
                foreach (var item in StateChanges)
                {
                    states.Add((item.Item1, previousTime, item.Item2 - previousTime));
                    previousTime = item.Item2;
                }
                return states.ToArray();
            }
        }

        //
        // The corresponding peer's timings.
        //
        public QuicStreamTiming? Peer { get; set; }

        //
        // Returns the sum of all the calculated times for individual layers.
        //
        public ulong TotalTime { get { return Times.Aggregate((temp, x) => temp + x); } }

        //
        // An estimate of the network cost from (Client.FirstRecv-Client.FirstSend)-(Server.FirstSend-Server.FirstRecv)
        //
        public TimestampDelta ClientNetworkTime
        {
            get
            {
                var LocalTime = FirstPacketRecv - FirstPacketSend;
                if (Peer!.ServerResponseTime < LocalTime)
                {
                    return LocalTime - Peer!.ServerResponseTime;
                }
                return TimestampDelta.Zero;
            }
        }
        public TimestampDelta ServerResponseTime { get { return FirstPacketSend - FirstPacketRecv; } }

        //
        // Triggers a state change and updates variables accordingly.
        //
        internal void UpdateToState(QuicStreamState newState, Timestamp time, bool ignorePrevious = false)
        {
            if (EncounteredError) return;
            if (State == newState) return;
            if (time < LastStateChangeTime)
            {
                if (!ignorePrevious)
                {
                    //Console.WriteLine("ERROR: Invalid state change from {0} to {1}", State, newState);
                    EncounteredError = true;
                }
                else if (State == QuicStreamState.Alloc && newState == QuicStreamState.QueueRecv)
                {
                    State = newState;
                    InitialStateTime = time;
                    LastStateChangeTime = time;
                }
                return;
            }
            if (newState == QuicStreamState.Frame && (State == QuicStreamState.IdleSent || State == QuicStreamState.IdleBoth))
            {
                State = QuicStreamState.ProcessSend; // Wasn't actually idle, but processing
            }
            if ((newState == QuicStreamState.Decrypt || newState == QuicStreamState.AppRecv) &&
                (State == QuicStreamState.IdleRecv || State == QuicStreamState.IdleBoth))
            {
                State = QuicStreamState.ProcessRecv; // Wasn't actually idle, but processing
            }
            var deltaT = time - LastStateChangeTime;
            Times[(int)State] += (ulong)deltaT.ToNanoseconds;
            StateChanges.Add((State, time));

            LastStateChangeTime = time;
            State = newState;
            if (newState == QuicStreamState.Alloc)
            {
                IsAllocated = true;
            }
        }

        internal void UpdateToIdle(Timestamp time)
        {
            if (EncounteredError) return;
            if (time < LastStateChangeTime)
            {
                //Console.WriteLine("ERROR: Invalid final time while in {0}", State);
                EncounteredError = true;
                return;
            }
            var deltaT = time - LastStateChangeTime;
            Times[(int)State] += (ulong)deltaT.ToNanoseconds;
            StateChanges.Add((State, time));

            LastStateChangeTime = time;
            if (FirstPacketRecv != Timestamp.Zero && FirstPacketSend != Timestamp.Zero)
            {
                if (SendShutdown && RecvShutdown)
                {
                    State = QuicStreamState.CleanUp;
                }
                else
                {
                    State = QuicStreamState.IdleBoth;
                }
            }
            else if (FirstPacketRecv != Timestamp.Zero)
            {
                State = QuicStreamState.IdleRecv;
            }
            else if (FirstPacketSend != Timestamp.Zero)
            {
                State = QuicStreamState.IdleSent;
            }
            else
            {
                State = QuicStreamState.Alloc;
            }
        }

        internal void FinalizeState(Timestamp time, bool trimTrailing = true)
        {
            if (EncounteredError) return;
            if (time < LastStateChangeTime)
            {
                //Console.WriteLine("ERROR: Invalid final time while in {0}", State);
                EncounteredError = true;
                return;
            }
            var deltaT = time - LastStateChangeTime;
            Times[(int)State] += (ulong)deltaT.ToNanoseconds;
            StateChanges.Add((State, time));
            LastStateChangeTime = time;
            IsFinalized = true;

            if (trimTrailing)
            {
                // Trim trailing CleanUp, Idle* and ProcessAppRecv states because they
                // generally don't attribute to total request time.
                while (StateChanges.Count > 1 &&
                      (StateChanges[^1].Item1 == QuicStreamState.CleanUp ||
                       StateChanges[^1].Item1 == QuicStreamState.IdleBoth ||
                       StateChanges[^1].Item1 == QuicStreamState.IdleRecv ||
                       StateChanges[^1].Item1 == QuicStreamState.IdleSent ||
                       StateChanges[^1].Item1 == QuicStreamState.ProcessAppRecv))
                {
                    deltaT = LastStateChangeTime - StateChanges[^2].Item2;
                    Times[(int)StateChanges[^1].Item1] -= (ulong)deltaT.ToNanoseconds;

                    StateChanges.RemoveAt(StateChanges.Count - 1);
                    LastStateChangeTime = StateChanges[^1].Item2;
                }
            }
        }
    }
}
