/*
    KHOMP generic endpoint/channel library.
    Copyright (C) 2007-2010 Khomp Ind. & Com.

  The contents of this file are subject to the Mozilla Public License Version 1.1
  (the "License"); you may not use this file except in compliance with the
  License. You may obtain a copy of the License at http://www.mozilla.org/MPL/

  Software distributed under the License is distributed on an "AS IS" basis,
  WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
  the specific language governing rights and limitations under the License.

  Alternatively, the contents of this file may be used under the terms of the
  "GNU Lesser General Public License 2.1" license (the “LGPL" License), in which
  case the provisions of "LGPL License" are applicable instead of those above.

  If you wish to allow use of your version of this file only under the terms of
  the LGPL License and not to allow others to use your version of this file under
  the MPL, indicate your decision by deleting the provisions above and replace them
  with the notice and other provisions required by the LGPL License. If you do not
  delete the provisions above, a recipient may use your version of this file under
  either the MPL or the LGPL License.

  The LGPL header follows below:

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this library; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/
/* ****************************************************************************** */
/* ******************* AUTO GENERATED FILE - DO NOT EDIT! *********************** */
/* ****************************************************************************** */

#include <verbose_traits.hpp>

std::string VerboseTraits::eventName(const Event value)
{
    switch(value)
    {
        case K_EV_CHANNEL_FREE:                                   return "EV_CHANNEL_FREE";
        case K_EV_CONNECT:                                        return "EV_CONNECT";
        case K_EV_DISCONNECT:                                     return "EV_DISCONNECT";
        case K_EV_CALL_SUCCESS:                                   return "EV_CALL_SUCCESS";
        case K_EV_CALL_FAIL:                                      return "EV_CALL_FAIL";
        case K_EV_NO_ANSWER:                                      return "EV_NO_ANSWER";
        case K_EV_BILLING_PULSE:                                  return "EV_BILLING_PULSE";
        case K_EV_SEIZE_SUCCESS:                                  return "EV_SEIZE_SUCCESS";
        case K_EV_SEIZE_FAIL:                                     return "EV_SEIZE_FAIL";
        case K_EV_SEIZURE_START:                                  return "EV_SEIZURE_START";
        case K_EV_CAS_LINE_STT_CHANGED:                           return "EV_CAS_LINE_STT_CHANGED";
        case K_EV_CAS_MFC_RECV:                                   return "EV_CAS_MFC_RECV";
        case K_EV_NEW_CALL:                                       return "EV_NEW_CALL";
        case K_EV_USER_INFORMATION:                               return "EV_USER_INFORMATION";
        case K_EV_USER_INFORMATION_EX:                            return "EV_USER_INFORMATION_EX";
        case K_EV_DIALED_DIGIT:                                   return "EV_DIALED_DIGIT";
        case K_EV_SIP_REGISTER_INFO:                              return "EV_SIP_REGISTER_INFO";
        case K_EV_RING_DETECTED:                                  return "EV_RING_DETECTED";
        case K_EV_ISDN_SUBADDRESSES:                              return "EV_ISDN_SUBADDRESSES";
        case K_EV_CALL_HOLD_START:                                return "EV_CALL_HOLD_START";
        case K_EV_CALL_HOLD_STOP:                                 return "EV_CALL_HOLD_STOP";
        case K_EV_SS_TRANSFER_FAIL:                               return "EV_SS_TRANSFER_FAIL";
        case K_EV_FLASH:                                          return "EV_FLASH";
        case K_EV_ISDN_PROGRESS_INDICATOR:                        return "EV_ISDN_PROGRESS_INDICATOR";
        case K_EV_CT_TRANSFER_SUCCESS:                            return "EV_CT_TRANSFER_SUCCESS";
        case K_EV_CT_TRANSFER_FAIL:                               return "EV_CT_TRANSFER_FAIL";
        case K_EV_DTMF_DETECTED:                                  return "EV_DTMF_DETECTED";
        case K_EV_DTMF_SEND_FINISH:                               return "EV_DTMF_SEND_FINISH";
        case K_EV_AUDIO_STATUS:                                   return "EV_AUDIO_STATUS";
        case K_EV_CADENCE_RECOGNIZED:                             return "EV_CADENCE_RECOGNIZED";
        case K_EV_END_OF_STREAM:                                  return "EV_END_OF_STREAM";
        case K_EV_PULSE_DETECTED:                                 return "EV_PULSE_DETECTED";
        case K_EV_POLARITY_REVERSAL:                              return "EV_POLARITY_REVERSAL";
        case K_EV_CALL_ANSWER_INFO:                               return "EV_CALL_ANSWER_INFO";
        case K_EV_COLLECT_CALL:                                   return "EV_COLLECT_CALL";
        case K_EV_SIP_DTMF_DETECTED:                              return "EV_SIP_DTMF_DETECTED";
        case K_EV_SIP_DATA:                                       return "EV_SIP_DATA";
        case K_EV_RECV_FROM_MODEM:                                return "EV_RECV_FROM_MODEM";
        case K_EV_NEW_SMS:                                        return "EV_NEW_SMS";
        case K_EV_SMS_INFO:                                       return "EV_SMS_INFO";
        case K_EV_SMS_DATA:                                       return "EV_SMS_DATA";
        case K_EV_SMS_SEND_RESULT:                                return "EV_SMS_SEND_RESULT";
        case K_EV_CALL_MPTY_START:                                return "EV_CALL_MPTY_START";
        case K_EV_CALL_MPTY_STOP:                                 return "EV_CALL_MPTY_STOP";
        case K_EV_GSM_COMMAND_STATUS:                             return "EV_GSM_COMMAND_STATUS";
        case K_EV_WATCHDOG_COUNT:                                 return "EV_WATCHDOG_COUNT";
        case K_EV_CHANNEL_FAIL:                                   return "EV_CHANNEL_FAIL";
        case K_EV_REFERENCE_FAIL:                                 return "EV_REFERENCE_FAIL";
        case K_EV_INTERNAL_FAIL:                                  return "EV_INTERNAL_FAIL";
        case K_EV_HARDWARE_FAIL:                                  return "EV_HARDWARE_FAIL";
        case K_EV_LINK_STATUS:                                    return "EV_LINK_STATUS";
        case K_EV_PHYSICAL_LINK_UP:                               return "EV_PHYSICAL_LINK_UP";
        case K_EV_PHYSICAL_LINK_DOWN:                             return "EV_PHYSICAL_LINK_DOWN";
        case K_EV_CLIENT_RECONNECT:                               return "EV_CLIENT_RECONNECT";
        case K_EV_CLIENT_AUDIOLISTENER_TIMEOUT:                   return "EV_CLIENT_AUDIOLISTENER_TIMEOUT";
        case K_EV_CLIENT_BUFFERED_AUDIOLISTENER_OVERFLOW:         return "EV_CLIENT_BUFFERED_AUDIOLISTENER_OVERFLOW";
        case K_EV_REQUEST_DEVICE_SECURITY_KEY:                    return "EV_REQUEST_DEVICE_SECURITY_KEY";
        case K_EV_DISK_IS_FULL:                                   return "EV_DISK_IS_FULL";
        case K_EV_VOIP_SEIZURE:                                   return "EV_VOIP_SEIZURE";
        case K_EV_SEIZURE:                                        return "EV_SEIZURE";
        case K_EV_FAX_CHANNEL_FREE:                               return "EV_FAX_CHANNEL_FREE";
        case K_EV_FAX_FILE_SENT:                                  return "EV_FAX_FILE_SENT";
        case K_EV_FAX_FILE_FAIL:                                  return "EV_FAX_FILE_FAIL";
        case K_EV_FAX_TX_TIMEOUT:                                 return "EV_FAX_TX_TIMEOUT";
        case K_EV_FAX_PAGE_CONFIRMATION:                          return "EV_FAX_PAGE_CONFIRMATION";
        case K_EV_FAX_REMOTE_INFO:                                return "EV_FAX_REMOTE_INFO";
        case K_EV_PONG:                                           return "EV_PONG";
        case K_EV_LOG_UPDATE:                                     return "EV_LOG_UPDATE";
    }
    return STG(FMT("event=%d") % ((int)value));
}

std::string VerboseTraits::commandName(const Command value)
{
    switch(value)
    {
        case K_CM_SEIZE:                                          return "CM_SEIZE";
        case K_CM_SYNC_SEIZE:                                     return "CM_SYNC_SEIZE";
        case K_CM_SIP_REGISTER:                                   return "CM_SIP_REGISTER";
        case K_CM_DIAL_DTMF:                                      return "CM_DIAL_DTMF";
        case K_CM_DISCONNECT:                                     return "CM_DISCONNECT";
        case K_CM_CONNECT:                                        return "CM_CONNECT";
        case K_CM_PRE_CONNECT:                                    return "CM_PRE_CONNECT";
        case K_CM_CAS_CHANGE_LINE_STT:                            return "CM_CAS_CHANGE_LINE_STT";
        case K_CM_CAS_SEND_MFC:                                   return "CM_CAS_SEND_MFC";
        case K_CM_SET_FORWARD_CHANNEL:                            return "CM_SET_FORWARD_CHANNEL";
        case K_CM_CAS_SET_MFC_DETECT_MODE:                        return "CM_CAS_SET_MFC_DETECT_MODE";
        case K_CM_DROP_COLLECT_CALL:                              return "CM_DROP_COLLECT_CALL";
        case K_CM_MAKE_CALL:                                      return "CM_MAKE_CALL";
        case K_CM_RINGBACK:                                       return "CM_RINGBACK";
        case K_CM_USER_INFORMATION:                               return "CM_USER_INFORMATION";
        case K_CM_USER_INFORMATION_EX:                            return "CM_USER_INFORMATION_EX";
        case K_CM_VOIP_SEIZE:                                     return "CM_VOIP_SEIZE";
        case K_CM_LOCK_INCOMING:                                  return "CM_LOCK_INCOMING";
        case K_CM_UNLOCK_INCOMING:                                return "CM_UNLOCK_INCOMING";
        case K_CM_LOCK_OUTGOING:                                  return "CM_LOCK_OUTGOING";
        case K_CM_UNLOCK_OUTGOING:                                return "CM_UNLOCK_OUTGOING";
        case K_CM_START_SEND_FAIL:                                return "CM_START_SEND_FAIL";
        case K_CM_STOP_SEND_FAIL:                                 return "CM_STOP_SEND_FAIL";
        case K_CM_END_OF_NUMBER:                                  return "CM_END_OF_NUMBER";
        case K_CM_SEND_SIP_DATA:                                  return "CM_SEND_SIP_DATA";
        case K_CM_SS_TRANSFER:                                    return "CM_SS_TRANSFER";
        case K_CM_GET_SMS:                                        return "CM_GET_SMS";
        case K_CM_PREPARE_SMS:                                    return "CM_PREPARE_SMS";
        case K_CM_SEND_SMS:                                       return "CM_SEND_SMS";
        case K_CM_SEND_TO_MODEM:                                  return "CM_SEND_TO_MODEM";
        case K_CM_CHECK_NEW_SMS:                                  return "CM_CHECK_NEW_SMS";
        case K_CM_ISDN_SEND_SUBADDRESSES:                         return "CM_ISDN_SEND_SUBADDRESSES";
        case K_CM_CT_TRANSFER:                                    return "CM_CT_TRANSFER";
        case K_CM_ENABLE_DTMF_SUPPRESSION:                        return "CM_ENABLE_DTMF_SUPPRESSION";
        case K_CM_DISABLE_DTMF_SUPPRESSION:                       return "CM_DISABLE_DTMF_SUPPRESSION";
        case K_CM_ENABLE_AUDIO_EVENTS:                            return "CM_ENABLE_AUDIO_EVENTS";
        case K_CM_DISABLE_AUDIO_EVENTS:                           return "CM_DISABLE_AUDIO_EVENTS";
        case K_CM_ENABLE_CALL_PROGRESS:                           return "CM_ENABLE_CALL_PROGRESS";
        case K_CM_DISABLE_CALL_PROGRESS:                          return "CM_DISABLE_CALL_PROGRESS";
        case K_CM_FLASH:                                          return "CM_FLASH";
        case K_CM_ENABLE_PULSE_DETECTION:                         return "CM_ENABLE_PULSE_DETECTION";
        case K_CM_DISABLE_PULSE_DETECTION:                        return "CM_DISABLE_PULSE_DETECTION";
        case K_CM_ENABLE_ECHO_CANCELLER:                          return "CM_ENABLE_ECHO_CANCELLER";
        case K_CM_DISABLE_ECHO_CANCELLER:                         return "CM_DISABLE_ECHO_CANCELLER";
        case K_CM_ENABLE_AGC:                                     return "CM_ENABLE_AGC";
        case K_CM_DISABLE_AGC:                                    return "CM_DISABLE_AGC";
        case K_CM_ENABLE_HIGH_IMP_EVENTS:                         return "CM_ENABLE_HIGH_IMP_EVENTS";
        case K_CM_DISABLE_HIGH_IMP_EVENTS:                        return "CM_DISABLE_HIGH_IMP_EVENTS";
        case K_CM_ENABLE_CALL_ANSWER_INFO:                        return "CM_ENABLE_CALL_ANSWER_INFO";
        case K_CM_DISABLE_CALL_ANSWER_INFO:                       return "CM_DISABLE_CALL_ANSWER_INFO";
        case K_CM_START_WATCHDOG:                                 return "CM_START_WATCHDOG";
        case K_CM_STOP_WATCHDOG:                                  return "CM_STOP_WATCHDOG";
        case K_CM_NOTIFY_WATCHDOG:                                return "CM_NOTIFY_WATCHDOG";
        case K_CM_WATCHDOG_COUNT:                                 return "CM_WATCHDOG_COUNT";
        case K_CM_HOLD_SWITCH:                                    return "CM_HOLD_SWITCH";
        case K_CM_MPTY_CONF:                                      return "CM_MPTY_CONF";
        case K_CM_MPTY_SPLIT:                                     return "CM_MPTY_SPLIT";
        case K_CM_SIM_CARD_SELECT:                                return "CM_SIM_CARD_SELECT";
        case K_CM_START_FAX_TX:                                   return "CM_START_FAX_TX";
        case K_CM_STOP_FAX_TX:                                    return "CM_STOP_FAX_TX";
        case K_CM_ADD_FAX_FILE:                                   return "CM_ADD_FAX_FILE";
        case K_CM_ADD_FAX_PAGE_BREAK:                             return "CM_ADD_FAX_PAGE_BREAK";
        case K_CM_START_FAX_RX:                                   return "CM_START_FAX_RX";
        case K_CM_STOP_FAX_RX:                                    return "CM_STOP_FAX_RX";
        case K_CM_RESET_LINK:                                     return "CM_RESET_LINK";
        case K_CM_CLEAR_LINK_ERROR_COUNTER:                       return "CM_CLEAR_LINK_ERROR_COUNTER";
        case K_CM_SEND_DEVICE_SECURITY_KEY:                       return "CM_SEND_DEVICE_SECURITY_KEY";
        case K_CM_RESET_MODEM:                                    return "CM_RESET_MODEM";
        case K_CM_ISDN_DISABLE_LINK:                              return "CM_ISDN_DISABLE_LINK";
        case K_CM_ISDN_ENABLE_LINK:                               return "CM_ISDN_ENABLE_LINK";
        case K_CM_SEND_DTMF:                                      return "CM_SEND_DTMF";
        case K_CM_STOP_AUDIO:                                     return "CM_STOP_AUDIO";
        case K_CM_HARD_RESET:                                     return "CM_HARD_RESET";
        case K_CM_SEND_TO_CTBUS:                                  return "CM_SEND_TO_CTBUS";
        case K_CM_RECV_FROM_CTBUS:                                return "CM_RECV_FROM_CTBUS";
        case K_CM_SEND_RANGE_TO_CTBUS:                            return "CM_SEND_RANGE_TO_CTBUS";
        case K_CM_SETUP_H100:                                     return "CM_SETUP_H100";
        case K_CM_MIXER:                                          return "CM_MIXER";
        case K_CM_CLEAR_MIXER:                                    return "CM_CLEAR_MIXER";
        case K_CM_PLAY_FROM_FILE:                                 return "CM_PLAY_FROM_FILE";
        case K_CM_RECORD_TO_FILE:                                 return "CM_RECORD_TO_FILE";
        case K_CM_PLAY_FROM_STREAM:                               return "CM_PLAY_FROM_STREAM";
        case K_CM_INTERNAL_PLAY:                                  return "CM_INTERNAL_PLAY";
        case K_CM_STOP_PLAY:                                      return "CM_STOP_PLAY";
        case K_CM_STOP_RECORD:                                    return "CM_STOP_RECORD";
        case K_CM_PAUSE_PLAY:                                     return "CM_PAUSE_PLAY";
        case K_CM_PAUSE_RECORD:                                   return "CM_PAUSE_RECORD";
        case K_CM_RESUME_PLAY:                                    return "CM_RESUME_PLAY";
        case K_CM_RESUME_RECORD:                                  return "CM_RESUME_RECORD";
        case K_CM_INCREASE_VOLUME:                                return "CM_INCREASE_VOLUME";
        case K_CM_DECREASE_VOLUME:                                return "CM_DECREASE_VOLUME";
        case K_CM_LISTEN:                                         return "CM_LISTEN";
        case K_CM_STOP_LISTEN:                                    return "CM_STOP_LISTEN";
        case K_CM_PREPARE_FOR_LISTEN:                             return "CM_PREPARE_FOR_LISTEN";
        case K_CM_PLAY_SOUND_CARD:                                return "CM_PLAY_SOUND_CARD";
        case K_CM_STOP_SOUND_CARD:                                return "CM_STOP_SOUND_CARD";
        case K_CM_MIXER_CTBUS:                                    return "CM_MIXER_CTBUS";
        case K_CM_PLAY_FROM_STREAM_EX:                            return "CM_PLAY_FROM_STREAM_EX";
        case K_CM_INTERNAL_PLAY_EX:                               return "CM_INTERNAL_PLAY_EX";
        case K_CM_ENABLE_PLAYER_AGC:                              return "CM_ENABLE_PLAYER_AGC";
        case K_CM_DISABLE_PLAYER_AGC:                             return "CM_DISABLE_PLAYER_AGC";
        case K_CM_START_STREAM_BUFFER:                            return "CM_START_STREAM_BUFFER";
        case K_CM_ADD_STREAM_BUFFER:                              return "CM_ADD_STREAM_BUFFER";
        case K_CM_STOP_STREAM_BUFFER:                             return "CM_STOP_STREAM_BUFFER";
        case K_CM_SEND_BEEP:                                      return "CM_SEND_BEEP";
        case K_CM_SEND_BEEP_CONF:                                 return "CM_SEND_BEEP_CONF";
        case K_CM_ADD_TO_CONF:                                    return "CM_ADD_TO_CONF";
        case K_CM_REMOVE_FROM_CONF:                               return "CM_REMOVE_FROM_CONF";
        case K_CM_RECORD_TO_FILE_EX:                              return "CM_RECORD_TO_FILE_EX";
        case K_CM_SET_VOLUME:                                     return "CM_SET_VOLUME";
        case K_CM_START_CADENCE:                                  return "CM_START_CADENCE";
        case K_CM_STOP_CADENCE:                                   return "CM_STOP_CADENCE";
        case K_CM_SET_INPUT_MODE:                                 return "CM_SET_INPUT_MODE";
        case K_CM_SET_LINE_CONDITION:                             return "CM_SET_LINE_CONDITION";
        case K_CM_SEND_LINE_CONDITION:                            return "CM_SEND_LINE_CONDITION";
        case K_CM_SET_CALLER_CATEGORY:                            return "CM_SET_CALLER_CATEGORY";
        case K_CM_DIAL_MFC:                                       return "CM_DIAL_MFC";
        case K_CM_VOIP_START_DEBUG:                               return "CM_VOIP_START_DEBUG";
        case K_CM_VOIP_STOP_DEBUG:                                return "CM_VOIP_STOP_DEBUG";
        case K_CM_VOIP_DUMP_STAT:                                 return "CM_VOIP_DUMP_STAT";
        case K_CM_ISDN_DEBUG:                                     return "CM_ISDN_DEBUG";
        case K_CM_PING:                                           return "CM_PING";
        case K_CM_LOG_UPDATE:                                     return "CM_LOG_UPDATE";
    }
    return STG(FMT("command=%d") % ((int)value));
}
