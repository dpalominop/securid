/******************************************************************************
*                      COPYRIGHT © 2002-2016 EMC CORPORATION                  *
*                         ---ALL RIGHTS RESERVED---                           *
*                                                                             *
* THIS SOFTWARE IS PROPRIETARY AND CONFIDENTIAL TO EMC CORPORATION., IS       *
* FURNISHED UNDER A LICENSE AND MAY BE USED AND COPIED ONLY IN ACCORDANCE THE *
* TERMS OF SUCH LICENSE AND WITH THE INCLUSION OF THE ABOVE COPYRIGHT NOTICE. *
* THIS SOFTWARE OR ANY OTHER COPIES THEREOF MAY NOT BE PROVIDED OR OTHERWISE  *
* MADE AVAILABLE TO ANY OTHER PERSON.  NO TITLE TO AND OWNERSHIP OF THE       *
* SOFTWARE IS HEREBY TRANSFERRED.                                             *
*                                                                             *
* THE INFORMATION IN THIS SOFTWARE IS SUBJECT TO CHANGE WITHOUT NOTICE AND    *
* SHOULD NOT BE CONSTRUED AS A COMMITMENT BY EMC CORPORATION.                 *
******************************************************************************/
/* acestatus.c : implementation file */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef WIN32
	#include <winsock2.h>
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif

// in NT this allows using the aceclnt.lib file for linking
#define USE_ACE_AGENT_API_PROTOTYPES
#include "acexport.h"
#include "sd_types.h"
#include "acclnt.h"
#include "status_display.h"
//#include "version.h"

#define IDP_SERVER_STATUS_UNCONNECTED "Unused (Server unconnected)"
#define IDP_SERVER_SUSPENDED          "Server not responding"
#define IDP_SERVER_LEGACY_MASTER      "Master using pre-release 5 protocols"
#define IDP_SERVER_LEGACY_SLAVE       "Slave using pre-release 5 protocols"
#define IDP_SERVER_DEFAULT_INIT       "Default Server during initial requests"
#define IDP_SERVER_DEFAULT_NOSERVERS  "Default Server due to failover"
#define IDP_NO_AUTHORITY              "This program requires Administrative or System Authority to be used."
#define	IDP_SERVER_STATUS_NORMAL      "Available for Authentications"
#define	IDP_SERVER_STATUS_FAILOVER    "For Failover only"
#define IDP_SERVER_STATUS_UNUSED      "Unused"
#define IDP_SERVER_STATUS_NOT_IMPLEMENTED      "TCP - Status Display not implemented"

#define MAX_LEN 256
#define ENV_VAR_LENGTH 4

// Returns true for UDP and false for TCP
int getProtocol()
{
	char *isUDP = getenv("USEUDP_ENV_VAR");
	#ifdef SunOS
		if( (isUDP != NULL) && strlen(isUDP) == ENV_VAR_LENGTH &&
	#else
		#ifdef HPUX
			if( (isUDP != NULL) && strlen(isUDP) == ENV_VAR_LENGTH &&
		#else
			if( (isUDP != NULL) && strnlen(isUDP, MAX_LEN) == ENV_VAR_LENGTH &&
		#endif
	#endif
		(strncmp(isUDP, "true", ENV_VAR_LENGTH) == 0 || 
		strncmp(isUDP, "TRUE", ENV_VAR_LENGTH) == 0) )
	{	
	return TRUE;
	}
	else 
	{
		return FALSE;
	}
}

int
main(int argc, char **argv)
{
    int nExitStatus = EXIT_SUCCESS;
    int i;
    S_status_display m_statdsp;
    SD_BOOL bSomeServerGood = SD_FALSE;
    int letter;

    if (AceInitialize() != ACE_SUCCESS) 
    {
        (void) fprintf(stdout,"can't connect to ACE/Server \n\n");
        // Should not exist, we should get minimal info, if possible
    }

    (void) memset (&m_statdsp,0,sizeof(m_statdsp));

    m_statdsp.u32Size = (SD_U32) sizeof(m_statdsp);
    /* version of status_display struct is determined by the size*/

    if (AceAgentStatusDisplay(&m_statdsp) != ACE_SUCCESS)
    {
        (void) fprintf(stderr," \nError can't get to ACE/Server Status \n\n");
        (void) AceShutdown(NULL);
        exit(EXIT_FAILURE);
    }
    
    /*
      now convert the ints to host order
      m_version        = m_statdsp.config_version;
      m_struct_length  = sizeof(configure.config);
      m_acmmaxretries  = m_statdsp.acmmaxretries;
      m_acmmaxservers  = m_statdsp.acmmaxservers;
      this max servers is from sdconf.rec, so either 1 or 2
      m_acmbasetimeout = m_statdsp.acmbasetimeout;
      m_use_des        = m_statdsp.use_des ? "Yes":"No";
      m_trusted        = m_statdsp.trusted;
      m_no_badprns     = ntohl(configure.config.no_badprns);
      m_acmservice     = m_statdsp.acmservice;
      m_acmprotocol    = m_statdsp.acmprotocol;
      m_acmport        = (SD_I32) m_statdsp.acmport;

      setting the m-protocol_ver (the protocol used by the agent)
      is made complicated because the only field available is the 
      m_statdsp.server_hi_protocol which is only set on an upgrade!!
      (It would be better to have the protocol_version field)
      For this reason we compute the version here.
    */

	/*
    while ((letter = getopt(argc, argv, "t")) != -1)
    {
        switch (letter) {
        case 't':
            (void) printf("%d", (m_statdsp.acmmaxretries)*(m_statdsp.acmbasetimeout));
            (void) AceShutdown(NULL);
            exit(0);
        default:
            break;
        }
    }

	*/

	(void) fprintf(stderr,"\nRSA ACE/Server Limits");
    (void) fprintf(stderr,"\n---------------------\n");
    (void) fprintf(stderr,"\tConfiguration Version : %d ",m_statdsp.config_version);

    (void) fprintf(stderr,"\tClient Retries : %d ", m_statdsp.acmmaxretries);
    (void) fprintf(stderr,"\n\tClient Timeout : %d ",m_statdsp.acmbasetimeout);
    (void) fprintf(stderr,"\t\tDES Enabled : %s ",m_statdsp.use_des ? "Yes":"No");
    (void) fprintf(stderr,"\n\nRSA ACE/Static Information");
    (void) fprintf(stderr,"\n--------------------------\n");
    (void) fprintf(stderr,"\tService : %s ",m_statdsp.acmservice);
    (void) fprintf(stderr,"\tProtocol : %s ",m_statdsp.acmprotocol);
    (void) fprintf(stderr,"\tPort Number : %d ",m_statdsp.acmport);
    (void) fprintf(stderr,"\n\nRSA ACE/Dynamic Information");
    (void) fprintf(stderr,"\n---------------------------\n");

    if (0 == m_statdsp.server_release_from_server[0])
    {
        (void) fprintf(stderr,"\tServer Release : N/A ");
    }
    else
    {
    	(void) fprintf(stderr,"\tServer Release : %c.%c.%c.%c ",
                       m_statdsp.server_release_from_server[0],
                       m_statdsp.server_release_from_server[1],
                       m_statdsp.server_release_from_server[2],
                       m_statdsp.server_release_from_server[3]);
    }


    if ((m_statdsp.config_version >= 12) || (m_statdsp.server_hi_protocol >= 5))
    {
        (void) fprintf(stderr,"\tCommunication : 5");
    }
    else
    {
        (void) fprintf(stderr,"\tCommunication : 2");
    }

    (void) fprintf(stderr,"\n\nRSA ACE/Server List");
    (void) fprintf(stderr,"\n-------------------\n");
	      
    for (i = 0; i < m_statdsp.acmmaxservers; i++)
    {
        struct in_addr addr;
        int master;
        int slave;
        int primary;
            
        if (i > 0)
        {
            (void) fprintf(stderr,"\n------------------------------------------------------------------------------\n");
        }
        
       
        
        (void) fprintf(stderr,"\tServer Name :           %s\n",m_statdsp.acm_servers[i].hostname);
        addr.s_addr = m_statdsp.acm_servers[i].addr;
        (void) fprintf(stderr,"\tServer Address :        %s\n", inet_ntoa(addr));
        addr.s_addr = m_statdsp.acm_servers[i].active_addr;
        (void) fprintf(stderr,"\tServer Active Address : %s\n", inet_ntoa(addr));

        primary = m_statdsp.acm_servers[i].display_status & DISP_STATUS_PRIMARY;

        master = slave = 0;

        if (m_statdsp.acm_servers[i].display_status & DISP_MSTR_SLAVE)
        {
            if (0 == i)
            {
                master = 1;
            }
            else
            {
                slave = 1;
            }
        }
            
        (void) fprintf(stderr,"\tMaster : %s ",master?"Yes":"No");
        (void) fprintf(stderr,"\tSlave : %s ",slave?"Yes":"No");
        (void) fprintf(stderr,"\tPrimary : %s ",primary?"Yes":"No");
        (void) fprintf(stderr,"\n\tUsage : ");

		if(getProtocol())	{
			if ((m_statdsp.config_version < 12) &&
				(m_statdsp.server_hi_protocol < 5))
			{
				if (0 == i) /* Master (or acting that way)*/
				{
					(void) fprintf(stderr,IDP_SERVER_LEGACY_MASTER);
				}
				else if ((1 == i) && (slave == 1))
				{
					(void) fprintf(stderr,IDP_SERVER_LEGACY_SLAVE);
				}
				else
				{
					(void) fprintf(stderr,IDP_SERVER_STATUS_UNUSED);
				}
	                
				(void) fprintf(stderr,"\n\n");
				break;
			}


			if ((0 == i) && !(m_statdsp.acm_servers[i].display_status & DISP_STATUS_SELECTABLE))
			{
				int i2;
				/* first server seems "UNUSED" etc...but it might be used!*/
				for (i2 = 1; i2 < DISP_MAX_SERVERS; i2++)
				{
					if ((m_statdsp.acm_servers[i2].display_status &
						 (DISP_STATUS_SELECTABLE | DISP_STATUS_EMERGENCY))
						&& (0 != m_statdsp.acm_servers[i2].active_addr))
					{
						bSomeServerGood = SD_TRUE;
						break;
						/*
						  :BUG: in API..emergency in display_status
						  may be set for priority 0 server
						  if its active addr is  non zero
						  we test the active addr here anyway so the bug
						  can be fixed
						*/
					}
				}

				if (!bSomeServerGood)
				{
					if (0 == m_statdsp.server_release_from_server[0])
					{
                		/*
						  did not get the server Capability yet
						  so usually not an error situation
						*/
						(void) fprintf(stderr,IDP_SERVER_DEFAULT_INIT);
					}
					else
					{
						(void) fprintf(stderr,IDP_SERVER_DEFAULT_NOSERVERS);
					}
					(void) fprintf(stderr,"\n\n");
					break;
				}
			}  

			if (0 != m_statdsp.acm_servers[i].active_addr)
			{
				if (m_statdsp.acm_servers[i].display_status & DISP_STATUS_SELECTABLE)
				{
					(void) fprintf(stderr,IDP_SERVER_STATUS_NORMAL);
				}
				else if (m_statdsp.acm_servers[i].display_status & DISP_STATUS_EMERGENCY)
				{
					(void) fprintf(stderr,IDP_SERVER_STATUS_FAILOVER);
				}
				else if (m_statdsp.acm_servers[i].display_status & DISP_STATUS_SUSPENDED)
				{
					(void) fprintf(stderr,IDP_SERVER_SUSPENDED);
				}
				else
				{
					(void) fprintf(stderr,IDP_SERVER_STATUS_UNUSED);
				}
			}
			else
			{
				(void) fprintf(stderr,IDP_SERVER_STATUS_UNCONNECTED);
			}
		}
		else
			(void) fprintf(stderr, IDP_SERVER_STATUS_NOT_IMPLEMENTED);
    }

	(void)AceShutdown(NULL);
    return nExitStatus;
}

