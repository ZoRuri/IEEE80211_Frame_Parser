#include <QCoreApplication>
#include <QDebug>

#include <arpa/inet.h>
#include <pcap.h>
#include <ieee80211.h>

#define RADIOTAPLEN *(data + 2)

void IEEE80211_Frame_Parser(const u_char *data, pcap_pkthdr *pkthdr);

void IEEE80211_MGT_Frame(const u_char *data, ieee80211_frame *fdh, pcap_pkthdr *pkthdr);
void IEEE80211_CTL_Frame(const u_char *data, ieee80211_frame *fdh);
void IEEE80211_DATA_Frame(const u_char *data, ieee80211_frame *fdh);

ieee80211_frame *IEEE80211_DS_ADDR(const u_char *data);
void IEEE80211_Information_Elements(const u_char *data, int datapoint, pcap_pkthdr *pkthdr);

QString MacADDR(u_int8_t* ADDR);
QString RSN_MacOUI(const u_char* OUI);

void MGT_Timestamp(const u_char *data, int datapoint);
void MGT_Beacon_Interval(const u_char *data, int datapoint);
void MGT_Capability_Info(const u_char *data, int datapoint);

const char *RSN_Cipher_Suite[] = {"",
    "WEP",      /* 1 */
    "TKIP",     /* 2 */
    "WRAP",     /* 3 */
    "CCMP",     /* 4 */
    "WEP-104",  /* 5 */
};

const char *RSN_Auth_Key[] = {"",
    "802.1X",           /* 1 */
    "PSK",              /* 2 */
    "FT over 802.1X",   /* 3 */
};

const char *Auth_Algo[] = {
    "Open System",      /* 0 */
    "Shared Key",       /* 1 */
};

const char *Status_Code[] = {
    "Successful",                                           /*  0 */
    "Unspecified failure",                                  /*  1 */
    "Reserved",                                             /*  2 */
    "Reserved",                                             /*  3 */
    "Reserved",                                             /*  4 */
    "Reserved",                                             /*  5 */
    "Reserved",                                             /*  6 */
    "Reserved",                                             /*  7 */
    "Reserved",                                             /*  8 */
    "Reserved",                                             /*  9 */
    "Cannot support all requested capabilities in the Capability "
    "Information field",                                    /* 10 */
    "Reassociation denied due to inability to confirm that "
    "association exists",                                   /* 11 */
    "Association denied due to reason outside the scope of "
    "this standard",                                        /* 12 */
    "Responding STA does not support the specified "
    "authentication algorithm",                             /* 13 */
    "Received an Authentication frame with authentication ",
    "transaction sequence number out of expected sequence", /* 14 */
    "Authentication rejected because of challenge failure", /* 15 */
    "Authentication rejected due to timeout waiting for "
    "next frame in sequence",                               /* 16 */
    "Association denied because AP is unable to handle "
    "additional associated stations",                       /* 17 */
    "Association denied due to requesting STA not supporting all of "
    "the data rates in the BSSBasicRateSet parameter",      /* 18 */
    "Association denied due to requesting STA not supporting "
    "the short preamble option",                            /* 19 */
    "Association denied due to requesting STA not supporting "
    "the PBCC modulation option",                           /* 20 */
    "Association denied due to requesting STA not supporting "
    "the Channel Agility option",                           /* 21 */
    "Association request rejected because Spectrum Management "
    "capability is required",                               /* 22 */
    "Association request rejected because the information "
    "in the Power Capability element is unacceptable",      /* 23 */
    "Association request rejected because the information "
    "in the Supported Channels element is unacceptable",    /* 24 */
    "Association denied due to requesting STA not supporting "
    "the Short Slot Time option",                           /* 25 */
    "Association denied due to requesting STA not supporting "
    "the DSSS-OFDM option",                                 /* 26 */
    "Reserved",                                             /* 27 */
    "Reserved",                                             /* 28 */
    "Reserved",                                             /* 29 */
    "Reserved",                                             /* 30 */
    "Reserved",                                             /* 31 */
    "Unspecified, QoS-related failure",                     /* 32 */
    "Association denied because QoS AP has insufficient bandwidth "
    "to handle another QoS STA",                            /* 33 */
    "Association denied due to excessive frame loss rates and/or "
    "poor conditions on current operating channel",         /* 34 */
    "Association (with QoS BSS) denied because the requesting "
    "STA does not support the QoS facility",                /* 35 */
    "Reserved",                                             /* 36 */
    "The request has been decline",                         /* 37 */
    "The request has not been successful as one or more "
    "parameters have invalid values",                       /* 38 */
    "The TS has not been created because the request cannot be "
    "honored; however, a suggested TSPEC is provided so that the "
    "initiating STA may attempt to set another TS with the suggested "
    "changes to the TSPEC",                                 /* 39 */
    "Invalid information element",                          /* 40 */
    "Invalid group cipher",                                 /* 41 */
    "Invalid pairwise cipher",                              /* 42 */
    "Invalid AKMP",                                         /* 43 */
    "Unsupported RSN information element version",          /* 44 */
    "Invalid RSN information element capabilities",         /* 45 */
    "Cipher suite rejected because of security policy",     /* 46 */
    "The TS has not been created; however, the HC may be capable of "
    "creating a TS, in response to a request, after the "
    "time indicated in the TS Delay element",               /* 47 */
    "Direct link is not allowed in the BSS by policy",      /* 48 */
    "Destination STA is not present within this QBSS",      /* 49 */
    "The Destination STA is not a QoS STA",                 /* 50 */
    "Association denied because the ListenInterval is "
    "too large",                                            /* 51 */

    /*
     * reference : http://www.ie.itcr.ac.cr/acotoc/Ingenieria/Lab%20TEM%20II/Antenas/Especificacion%20802%2011-2007.pdf
     */
};

const char *Reason_Code[] = {
    "Reserved",                                             /*  0 */
    "Unspecified reason",                                   /*  1 */
    "Previous authentication no longer valid",              /*  2 */
    "Deauthenticated because sending STA is leaving "
    "(or has left) IBSS or ESS",                            /*  3 */
    "Disassociated due to inactivity",                      /*  4 */
    "Disassociated because AP is unable to handle all currently "
    "associated STAs",                                      /*  5 */
    "Class 2 frame received from nonauthenticated STA",     /*  6 */
    "Class 3 frame received from nonassociated STA",        /*  7 */
    "Disassociated because sending STA is leaving "
    "(or has left) BSS",                                    /*  8 */
    "STA requesting (re)association is not authenticated "
    "with responding STA",                                  /*  9 */
    "Disassociated because the information in the Power Capability "
    "element is unacceptable",                              /* 10 */
    "Disassociated because the information in the Supported Channels "
    "element is unacceptable",                              /* 11 */
    "Reserved",                                             /* 12 */
    "Invalid information element",                          /* 13 */
    "Message integrity code (MIC) failure",                 /* 14 */
    "4-Way Handshake timeout",                              /* 15 */
    "Group Key Handshake timeout",                          /* 16 */
    "Information element in 4-Way Handshake different from "
    "(Re)Association Request/Probe Response/Beacon frame",  /* 17 */
    "Invalid group cipher",                                 /* 18 */
    "Invalid pairwise cipher",                              /* 19 */
    "Invalid AKMP",                                         /* 20 */
    "Unsupported RSN information element version",          /* 21 */
    "Invalid RSN information element capabilities",         /* 22 */
    "IEEE 802.1X authentication failed",                    /* 23 */
    "Cipher suite rejected because of the security policy"  /* 24 */
    "Reserved",                                             /* 25 */
    "Reserved",                                             /* 26 */
    "Reserved",                                             /* 27 */
    "Reserved",                                             /* 28 */
    "Reserved",                                             /* 29 */
    "Reserved",                                             /* 30 */
    "Reserved",                                             /* 31 */
    "Disassociated for unspecified, QoS-related reason",    /* 32 */
    "Disassociated because QoS AP lacks sufficient bandwidth "
    "for this QoS STA",                                     /* 33 */
    "Disassociated because excessive number of frames need to "
    "be acknowledged, but are not acknowledged due to "
    "AP transmissions and/or poor channel conditions",      /* 34 */
    "Disassociated because STA is transmitting outside "
    "the limits of its TXOPs",                              /* 35 */
    "Requested from peer STA as the STA is leaving the BSS "
    "(or resetting)",                                       /* 36 */
    "Requested from peer STA as it does not want to use "
    "the mechanism",                                        /* 37 */
    "Requested from peer STA as the STA received frames using "
    "the mechanism for which a setup is required",          /* 38 */
    "Requested from peer STA due to timeout",               /* 39 */
    "Reserved",                                             /* 40 */
    "Reserved",                                             /* 41 */
    "Reserved",                                             /* 42 */
    "Reserved",                                             /* 43 */
    "Reserved",                                             /* 44 */
    "Peer STA does not support the requested cipher suite", /* 45 */

    /*
     * reference : http://www.ie.itcr.ac.cr/acotoc/Ingenieria/Lab%20TEM%20+II/Antenas/Especificacion%20802%2011-2007.pdf
     */
};

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    const char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = "wlan4";
    pcap_t *handle;
    struct pcap_pkthdr *pkthdr;
    const u_char *data;

    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

    while(true)
    {
        pcap_next_ex(handle, &pkthdr, &data);

        IEEE80211_Frame_Parser(data, pkthdr);
    }
}

void IEEE80211_Frame_Parser(const u_char *data, pcap_pkthdr *pkthdr) {
    /* Distribute System (DS) */
    ieee80211_frame *fdh = IEEE80211_DS_ADDR(data);

    /* Frame Control Field */
    switch(fdh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)  /* Frame Type */
    {
        case IEEE80211_FC0_TYPE_MGT:    /* Management Frame */
            qDebug() << "Management";
            IEEE80211_MGT_Frame(data, fdh, pkthdr);
            break;

        case IEEE80211_FC0_TYPE_CTL:    /* Control Frame */
            qDebug() << "Control";
            IEEE80211_CTL_Frame(data, fdh);
            break;

        case IEEE80211_FC0_TYPE_DATA:   /* Data Frame */
            qDebug() << "Data";
            IEEE80211_DATA_Frame(data, fdh);
            break;

        default:
            break;
    }
}

void IEEE80211_MGT_Frame(const u_char *data, ieee80211_frame *fdh, pcap_pkthdr *pkthdr) {
    /*
     *  Management frame subtype's fixed parameters contents
     *
     *               | AUTH_ALGO | AUTH_SEQ  | TIMESTAMP | BCON_ITVL | CPB_INFO  | LSTN_ITVL | CRNT_AP   | REASON | STATUS | AID |
     *  ASSOC_REQ    |           |           |           |           |     o     |     o     |           |        |        |     |
     *  ASSOC_RESP   |           |           |           |           |     o     |           |           |        |    o   |  o  |
     *  REASSOC_REQ  |           |           |           |           |     o     |     o     |     o     |        |        |     |
     *  REASSOC_RESP |           |           |           |           |     o     |           |           |        |    o   |  o  |
     *  PROBE_REQ    |           |           |           |           |           |           |           |        |        |     |
     *  PROBE_RESP   |           |           |     o     |     o     |     o     |           |           |        |        |     |
     *  BEACON       |           |           |     o     |     o     |     o     |           |           |        |        |     |
     *  DISASSOC     |           |           |           |           |           |           |           |    o   |        |     |
     *  AUTH         |     o     |     o     |           |           |           |           |           |        |    o   |     |
     *  DEAUTH       |           |           |           |           |           |           |           |    o   |        |     |
     *  ATIM         |           |           |           |           |           |           |           |        |        |     |
     */

    int datapoint = RADIOTAPLEN + sizeof(*fdh); /* radiotap length + frame length */

    /*  Management Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
            MGT_Capability_Info(data, datapoint);           datapoint += 2;
            /* Listen Interval */                           datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
            MGT_Capability_Info(data, datapoint);           datapoint += 2;
            Status_Code[*((u_int16_t*)(data + datapoint))]; datapoint += 2;
            /* Association ID */                            datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
            MGT_Capability_Info(data, datapoint);           datapoint += 2;
            /* Listen Interval */                           datapoint += 2;
            /* Current AP */                                datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
            MGT_Capability_Info(data, datapoint);           datapoint += 2;
            Status_Code[*((u_int16_t*)(data + datapoint))]; datapoint += 2;
            /* Association ID */                            datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
            /* NULL */
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
            MGT_Timestamp(data, datapoint);
            MGT_Beacon_Interval(data, datapoint);           datapoint += 10;
            MGT_Capability_Info(data, datapoint);           datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_BEACON:
            MGT_Timestamp(data, datapoint);
            MGT_Beacon_Interval(data, datapoint);           datapoint += 10;
            MGT_Capability_Info(data, datapoint);           datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_ATIM:
            return;
            break;

        case IEEE80211_FC0_SUBTYPE_DISASSOC:
            Reason_Code[*((u_int16_t*)(data + datapoint))]; datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_AUTH:
            Auth_Algo[*((u_int16_t*)(data + datapoint))];   datapoint += 2;
            /* Auth SEQ */                                  datapoint += 2;
            Status_Code[*((u_int16_t*)(data + datapoint))]; datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_DEAUTH:
            Reason_Code[*((u_int16_t*)(data + datapoint))]; datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_ACTION:
            break;

        case IEEE80211_FC0_SUBTYPE_ACTION_NOACK:
            break;
    }

    /* tagged parameters */
    IEEE80211_Information_Elements(data, datapoint, pkthdr);

}

void IEEE80211_CTL_Frame(const u_char *data, ieee80211_frame *fdh) {
    /* Control Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_BAR:
            break;

        case IEEE80211_FC0_SUBTYPE_BA:
            break;

        case IEEE80211_FC0_SUBTYPE_PS_POLL:
            break;

        case IEEE80211_FC0_SUBTYPE_RTS:
            break;

        case IEEE80211_FC0_SUBTYPE_CTS:
            break;

        case IEEE80211_FC0_SUBTYPE_ACK:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_END:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_END_ACK:
            break;
    }
}

void IEEE80211_DATA_Frame(const u_char *data, ieee80211_frame *fdh) {
    /* Data Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_DATA:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_ACK:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_POLL:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_ACPL:
            break;

        case IEEE80211_FC0_SUBTYPE_NODATA:
            break;

        case IEEE80211_FC0_SUBTYPE_CFACK:
            break;

        case IEEE80211_FC0_SUBTYPE_CFPOLL:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK:
            break;

        case IEEE80211_FC0_SUBTYPE_QOS:
            break;

        case IEEE80211_FC0_SUBTYPE_QOS_NULL:
            break;
    }
}

ieee80211_frame *IEEE80211_DS_ADDR(const u_char *data) {
    /*frames struct*/
    ieee80211_frame *fdh = (struct ieee80211_frame *)(data + RADIOTAPLEN);

    /*
     *  Data Frame - Address field contents
     *
     *  To Ds  | From DS | Addr 1 | Addr 2 | Addr 3 | Addr 4
     *    0    |  0      |  DA    | SA     | BSSID  | n/a
     *    0    |  1      |  DA    | BSSID  | SA     | n/a
     *    1    |  0      |  BSSID | SA     | DA     | n/a
     *    1    |  1      |  RA    | TA     | DA     | SA
     */

    switch(fdh->i_fc[1] & IEEE80211_FC1_DIR_MASK)    /* Distribute System (DS) */
    {
        case IEEE80211_FC1_DIR_NODS:    /* STA -> STA */
            qDebug() << "DA:" << MacADDR(fdh->i_addr1);
            qDebug() << "SA:" << MacADDR(fdh->i_addr2);
            qDebug() << "BSSID:" << MacADDR(fdh->i_addr3);
            break;

        case IEEE80211_FC1_DIR_TODS:    /* STA -> AP */
            qDebug() << "DA:" << MacADDR(fdh->i_addr3);
            qDebug() << "SA:" << MacADDR(fdh->i_addr2);
            qDebug() << "BSSID:" << MacADDR(fdh->i_addr1);
            break;

        case IEEE80211_FC1_DIR_FROMDS:  /* AP -> STA */
            qDebug() << "DA:" << MacADDR(fdh->i_addr1);
            qDebug() << "SA:" << MacADDR(fdh->i_addr3);
            qDebug() << "BSSID:" << MacADDR(fdh->i_addr2);
            break;

        case IEEE80211_FC1_DIR_DSTODS:  /* AP -> AP */
            ieee80211_frame_addr4 *fdh = (struct ieee80211_frame_addr4 *)(data + RADIOTAPLEN);
            qDebug() << "RA:" << MacADDR(fdh->i_addr1);
            qDebug() << "TA:" << MacADDR(fdh->i_addr2);
            qDebug() << "DA:" << MacADDR(fdh->i_addr3);
            qDebug() << "SA:" << MacADDR(fdh->i_addr4);
            break;
    }

    return fdh;
}

void IEEE80211_Information_Elements(const u_char *data, int datapoint, pcap_pkthdr *pkthdr) {
    /* Check Elements ID */
    while(datapoint < (int)pkthdr->caplen - 4)      /* Packet Length - Frame check sequence(4Bytes) */
    {

        int ELEMID = *(data + datapoint);
        ++datapoint;
        int ELELen = *(data + datapoint);
        ++datapoint;

        switch(ELEMID)
        {
            case IEEE80211_ELEMID_SSID:
                {
                    QString SSID;
                    unsigned int SSIDLen = ELELen;
                    for (unsigned int i = 0; i < SSIDLen; ++i)
                    {
                        SSID.append(*(data + datapoint + i));
                    }
                    qDebug() << SSID;
                    break;
                }

            case IEEE80211_ELEMID_RATES:        /* Supported Rate 500Kbps */
            /*
             * 802.11b is started by 0x80   ex) 0x82 = 1Mbps
             */
                {
                    double Rates[ELELen];
                    for (int i = 0; i < ELELen; ++i)
                    {
                        if (*(data + datapoint + i) & 0x80)     /* 802.11b */
                            Rates[i] = (double)(*(data + datapoint + i) - 0x80)/2;
                        else
                            Rates[i] = (*(data + datapoint + i)) >> 1;
                    }
                }
                break;

            case IEEE80211_ELEMID_FHPARMS:
                break;

            case IEEE80211_ELEMID_DSPARMS:      /* DS Prameter Set (Channel) */
                qDebug() << "Channel:" << *(data + datapoint);
                break;

            case IEEE80211_ELEMID_CFPARMS:
                break;

            case IEEE80211_ELEMID_TIM:          /* Traffic Indication Map */
                qDebug() << "DTIM Count:" << *(data + datapoint);           /* DTIM Count */
                qDebug() << "DTIM Period:" << *(data + datapoint + 1);      /* DTIM Period */
                qDebug() << "Bitmap Control:" << *(data + datapoint + 2);   /* Bitmap Control */
                                                                            /* Partial Virtual Bitmap */
                break;

            case IEEE80211_ELEMID_IBSSPARMS:
                break;

            case IEEE80211_ELEMID_COUNTRY:
                break;

            case IEEE80211_ELEMID_CHALLENGE:
                break;

            case IEEE80211_ELEMID_PWRCNSTR:
                break;

            case IEEE80211_ELEMID_PWRCAP:
                break;

            case IEEE80211_ELEMID_TPCREQ:
                break;

            case IEEE80211_ELEMID_TPCREP:
                break;

            case IEEE80211_ELEMID_SUPPCHAN:
                break;

            case IEEE80211_ELEMID_CSA:
                break;

            case IEEE80211_ELEMID_MEASREQ:
                break;

            case IEEE80211_ELEMID_MEASREP:
                break;

            case IEEE80211_ELEMID_QUIET:
                break;

            case IEEE80211_ELEMID_IBSSDFS:
                break;

            case IEEE80211_ELEMID_ERP:
                break;

            case IEEE80211_ELEMID_HTCAP:
                break;

            case IEEE80211_ELEMID_QOS:
                break;

            case IEEE80211_ELEMID_RSN:          /* Robust Secure Network (Encryption & Authentication) */
                {
                    int offset = 0;

                    qDebug() << "RSN Version:" << *((u_int16_t*)(data + datapoint));                    offset += 2;
                    qDebug() << "Group_Cipher_OUI" << RSN_MacOUI(&*(data + datapoint + offset));        offset += 3;
                    qDebug() << "Group_Cipher" << RSN_Cipher_Suite[*(data + datapoint + offset)];       offset += 1;

                    int PairwireCount = *((u_int16_t*)(data + datapoint + offset));                     offset += 2;

                    for (int i = 0; i < PairwireCount; ++i)
                    {
                        qDebug() << "Pairwire OUI" << RSN_MacOUI(&*(data + datapoint + offset));        offset += 3;
                        qDebug() << "Pairwire:" << RSN_Cipher_Suite[*(data + datapoint + offset)];      offset += 1;
                    }

                    int AuthCount = *((u_int16_t*)(data + datapoint + offset));                         offset += 2;

                    for (int i = 0; i < AuthCount; ++i)
                    {
                        qDebug() << "Auth OUI" << RSN_MacOUI(&*(data + datapoint + offset));            offset += 3;
                        qDebug() << "Auth:" << RSN_Auth_Key[*(data + datapoint + offset)];              offset += 1;
                    }
                }
                break;

            case IEEE80211_ELEMID_XRATES:       /* Extended Supported Rates 500Kbps */
                {
                    double Rates[ELELen];
                    for (int i = 0; i < ELELen; ++i)
                    {
                        if (*(data + datapoint + i) & 0x80)     /* 802.11b */
                            Rates[i] = (double)(*(data + datapoint + i) - 0x80)/2;
                        else
                            Rates[i] = (*(data + datapoint + i)) >> 1;
                    }
                }
                break;

            case IEEE80211_ELEMID_HTINFO:
                break;

            case IEEE80211_ELEMID_TPC:
                break;

            case IEEE80211_ELEMID_CCKM:
                break;

            case IEEE80211_ELEMID_VENDOR:
                break;

        }

        datapoint += ELELen;

    }

}

QString MacADDR(u_int8_t* ADDR) {
    QString MacADDR;

    MacADDR.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", ADDR[0], ADDR[1], ADDR[2], ADDR[3], ADDR[4], ADDR[5]);

    return MacADDR;
}

QString RSN_MacOUI(const u_char* OUI) {
    QString MacOUI;

    MacOUI.sprintf("%02X-%02X-%02X", OUI[0], OUI[1], OUI[2]);

    return MacOUI;
}

inline void MGT_Timestamp(const u_char *data, int datapoint) {
    qDebug() << "Timestamp:" << hex << *((u_int64_t*)(data + datapoint));

}

inline void MGT_Beacon_Interval(const u_char *data, int datapoint) {
    qDebug() << "Beacon Interval:" << IEEE80211_BEACON_INTERVAL(data + datapoint) * 1.024 << "ms";
}

void MGT_Capability_Info(const u_char *data, int datapoint) {
    /* Capabilities Information */
    switch (IEEE80211_CAPABILITY(data + datapoint) & 0xFFFF)
    {
        case IEEE80211_CAPINFO_ESS:
            break;

        case IEEE80211_CAPINFO_IBSS:
            break;

        case IEEE80211_CAPINFO_CF_POLLABLE:
            break;

        case IEEE80211_CAPINFO_CF_POLLREQ:
            break;

        case IEEE80211_CAPINFO_PRIVACY:         /* WEP */
            break;

        case IEEE80211_CAPINFO_SHORT_PREAMBLE:
            break;

        case IEEE80211_CAPINFO_PBCC:
            break;

        case IEEE80211_CAPINFO_CHNL_AGILITY:
            break;

        case IEEE80211_CAPINFO_SPECTRUM_MGMT:
            break;

        case IEEE80211_CAPINFO_SHORT_SLOTTIME:
            break;

        case IEEE80211_CAPINFO_RSN:
            break;

        case IEEE80211_CAPINFO_DSSSOFDM:
            break;

        default:
            break;
    }
}
