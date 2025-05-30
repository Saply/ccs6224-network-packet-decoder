#define NULL 0
#define TCPDUMP_MAGIC 0xa1b2c3d4 /* Tcpdump Magic Number (Preamble)  */
#define PCAP_VERSION_MAJOR 2     /* Tcpdump Version Major (Preamble) */
#define PCAP_VERSION_MINOR 4     /* Tcpdump Version Minor (Preamble) */

#define DLT_NULL 0   /* Data Link Type Null  */
#define DLT_EN10MB 1 /* Data Link Type for Ethernet II 100 MB and above */
#define DLT_EN3MB 2  /* Data Link Type for 3 Mb Experimental Ethernet */

// Ethernet Header
#define ETHER_ADDR_LEN 6
#include <stdio.h>
#include <iostream>
#include <fstream>
using namespace std;

FILE *input;
FILE* output;

typedef struct packet_header
{
    unsigned int magic;           /* Tcpdump Magic Number	*/
    unsigned short version_major; /* Tcpdump Version Major */
    unsigned short version_minor; /* Tcpdump Version Minor */
    unsigned int thiszone;        /* GMT to Local Correction */
    unsigned int sigfigs;         /* Accuracy of timestamps */
    unsigned int snaplen;         /* Max Length of Portion of Saved Packet */
    unsigned int linktype;        /* Data Link Type */
} hdr;

typedef struct packet_timestamp
{
    unsigned int tv_sec;  /* Timestamp in Seconds */
    unsigned int tv_usec; /* Timestamp in Micro Seconds */
    /* Total Length of Packet Portion (Ethernet Length until the End of Each Packet) */
    unsigned int caplen;
    unsigned int len; /* Length of the Packet (Off Wire) */
} tt;

typedef struct ether_header
{
    unsigned char edst[ETHER_ADDR_LEN]; /* Ethernet Destination Address */
    unsigned char esrc[ETHER_ADDR_LEN]; /* Ethernet Source Address */
    unsigned short etype;               /* Ethernet Protocol Type */
} eth;

int main(int argc, char *argv[])
{

    unsigned int remain_len = 0;
    unsigned char temp = 0, hlen, version, tlen;
    int i, count = 0;

    struct packet_header hdr;   /* Initialize Packet Header Structure */
    struct packet_timestamp tt; /* Initialize Timestamp Structure */
    struct ether_header eth;    /* Initialize Ethernet Structure */
    unsigned char buff, array[1500];

    input = fopen("1000Packets.pcap", "rb"); /* Open Input File */
    output = fopen("xyzzzzz.pcap", "wb");
    if (fopen == NULL)
        cout << "Cannot open saved windump file" << endl;
    else
    {
        fread((char *)&hdr, sizeof(hdr), 1, input); /* Read & Display Packet Header Information */

        cout << "\n********** ********** PACKET HEADER ********** ***********" << endl;
        cout << "Preamble " << endl;
        cout << "Packet Header Length : " << sizeof(hdr) << endl;
        cout << " Magic Number : " << hdr.magic << endl;
        cout << "Version Major : " << hdr.version_major << endl;
        cout << "Version Minor : " << hdr.version_minor << endl;
        cout << "GMT to Local Correction : " << hdr.thiszone << endl;
        cout << "Jacked Packet with Length of : " << hdr.snaplen << endl;
        cout << "Accuracy to Timestamp   :  " << hdr.sigfigs << endl;
        cout << "Data Link Type (Ethernet Type II = 1)  : " << hdr.linktype << endl;

        /* Use While Loop to Set the Packet Boundary */
        while (fread((char *)&tt, sizeof(tt), 1, input)) /* Read & Display Timestamp Information */
        {
            ++count;

            cout << "********** ********** TIMESTAMP & ETHERNET FRAME ********** ***********" << endl;
            cout << " Packet Number: " << count << endl; /* Display Packet Number */
            cout << " The Packets  are Captured in : " << tt.tv_sec << " Seconds" << endl;
            cout << "The Packets  are Captured in : " << tt.tv_usec << " Micro-seconds" << endl;

            /* Use caplen to Find the Remaining Data Segment */
            cout << "The Actual Packet Length: " << tt.caplen << "Bytes" << endl;
            cout << "Packet Length (Off Wire): " << tt.len << "Bytes" << endl;

            fread((char *)&eth, sizeof(eth), 1, input); /* Read & display ethernet header information */
            cout << "Ethernet Header Length  : " << sizeof(eth) << " bytes" << endl;

            // You may want to remove the  MAC Address output in your code
            printf("MAC Destination Address	: [hex] %x :%x :%x :%x :%x :%x \n\t\t\t  [dec] %d :%d :%d :%d :%d :%d\n",
                   eth.edst[0], eth.edst[1],
                   eth.edst[2], eth.edst[3], eth.edst[4], eth.edst[5], eth.edst[0], eth.edst[1],
                   eth.edst[2], eth.edst[3], eth.edst[4], eth.edst[5], eth.edst[6]);

            printf("MAC Source Address	: [hex] %x :%x :%x :%x :%x :%x \n\t\t\t  [dec] %d :%d :%d :%d :%d :%d\n",
                   eth.esrc[0], eth.esrc[1], eth.esrc[2],
                   eth.esrc[3], eth.esrc[4], eth.esrc[5], eth.esrc[0], eth.esrc[1],
                   eth.esrc[2], eth.esrc[3], eth.esrc[4], eth.esrc[5]);

            printf("\n\n C Cout\n\n");
            cout << "MAC Address " << eth.esrc[0] << " " << eth.esrc[1] << endl;

            fwrite(&hdr, sizeof(hdr), 1, output);

            for (i = 0; i < tt.caplen - 14; i++)
            {
                fread((char *)&buff, sizeof(buff), 1, input);
                printf(" %x", buff); // you may remove the printf line if neccessary
                array[i] = buff;
            }

            // *********************** FOR ASSIGNMENT NOT INVOLVING WRITING BACK TO A FILE ******
            // *************************BEGIN MODIFICATION HERE.********************************************
            //  *********************** It is recommended to add Your Code here **********
            // ****Nevertheless, in some of the questions you may need to add some code
            //  ** elsewhere in the program. ********************
            //  ......  Your Code

            if (((int)array[12] <= 127) && ((int)array[16] <= 127) && (eth.etype == 8)) {
                cout << "Source IP and Destination IP is class A" << "\n";
                fwrite(&tt, sizeof(tt), 1, output);
                fwrite(&eth, sizeof(eth), 1, output);
                for (int i = 0; i < tt.caplen - 14; i++) {
                    fwrite(&array[i], sizeof(unsigned char), 1, output);
                }
            }


            //  ****** END OF MODIFICATION HERE **********************
            //  WARNING: Try not to modify the while loop , the fread statement as you may affect
            //  the packet boundary and the whole program may not work after that.

            printf("\n ");

        } // end while
    }     // end main else

    fclose(input); // Close input file
    fclose(output);

    return (0);
}
