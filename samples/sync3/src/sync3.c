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
/* sync2.c uses SD_Lock, SD_Pin, SD_Check, SD_Next to explain the handling of Pin modea,
 and AceSetAuthAttr, AceSetCredential, SD_ClientCheck to explain to retrieve extended information from Auth Manager */

/* 
 * This program demonstrates the API by allowing users to 
 * log in, and it handles all the new pin parameters.
 * 
 * This program searches for sdconf.rec in the following locations;
 * the path pointed to by the environment variable VAR_ACE,
 * the /var/ace default path.
 *
 */

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define sleep(x)    Sleep(x*1000)
#define ENABLE_ECHO_INPUT 0x0004
#define ENABLE_LINE_INPUT 0x0002
#endif

#ifndef WIN32
#include <termio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// in NT this allows using the aceclnt.lib file for linking
#define USE_ACE_AGENT_API_PROTOTYPES
#include "acexport.h"
#include "sdacmvls.h"

#ifdef BLD_OFFLINEAUTH
#include "DASvcApiLoader.h"
#endif

int sd_echo_off(void);
int sd_echo_on(void);

#ifdef WIN32
    HANDLE hStdIn;
    DWORD OrigConsoleMode, ConsoleMode;
#endif

int fEcho = 1;

#define AUTH_CHALLENGE_USERNAME_STR \
  "Enter USERNAME: "

#define AUTH_CHALLENGE_PASSCODE_STR \
  "Enter PASSCODE: "

#define AUTH_CHALLENGE_NEXT_CODE_STR \
  "Wait for the tokencode to change,\n" \
  "then enter the new tokencode: "

#define AUTH_CHALLENGE_NEW_PIN_STR \
  "You must select a new PIN.\n" \
  "Do you want the system to generate\n" \
  "your new PIN? (y/n) [n] "

#define AUTH_CHALLENGE_NEW_PIN_ALPHA_SAME_STR \
  "Enter a new PIN of %d alphanumeric\n" \
  "characters: "

#define AUTH_CHALLENGE_NEW_PIN_ALPHA_STR \
  "Enter a new PIN between %d and %d alphanumeric\n" \
  "characters: "

#define AUTH_CHALLENGE_NEW_PIN_DIGITS_SAME_STR \
  "Enter a new PIN of %d digits: "

#define AUTH_CHALLENGE_NEW_PIN_DIGITS_STR \
  "Enter a new PIN between %d and %d digits: "

#define AUTH_CHALLENGE_NEW_PIN_SYS_STR \
  "To continue, you must accept a new PIN generated\n" \
  "by the system. Are you ready to have the\n" \
  "system generate your PIN? (y/n) [n] "

#define AUTH_CHALLENGE_CONFIRM_PIN_STR \
  "Re-enter new PIN to confirm: "

#define AUTH_CHALLENGE_NEW_SYS_PIN_PASSCODE_STR \
  "Wait for the tokencode to change,\n" \
  "then enter a new PASSCODE: "

#define AUTH_CHALLENGE_NEW_USER_PIN_PASSCODE_STR \
  "PIN accepted. Wait for the tokencode to\n" \
  "change, then enter a new PASSCODE: "

#define AUTH_CHALLENGE_SUCCESS_STR \
  "PASSCODE accepted.\n"

#define AUTH_CHALLENGE_ACCESS_DENIED_STR \
  "Access denied.\n"

#define AUTH_ERROR_MISC_STR \
  "Unexpected authentication error.\n"

#define AUTH_ERROR_BAD_PASSCODE_STR \
  "Access denied.\n"

#define AUTH_ERROR_BAD_TOKENCODE_STR \
  "Access denied.\n"

#define AUTH_ERROR_INVALID_PIN_STR \
  "Invalid PIN.\n"

#define AUTH_ERROR_CONFIRM_PIN_STR \
  "PIN did not match confirmation. Press Enter to continue.\n"

#define AUTH_ERROR_INVALID_ARG_STR \
  "Invalid argument.\n"

#define AUTH_CHALLENGE_NEW_PIN_USER_STR \
  "To continue you must enter a new PIN.\n" \
  "Are you ready to enter a new PIN? (y/n) [n]"

#define AUTH_CHALLENGE_NEW_SYS_PIN_DISPLAY_STR \
  "\n\nYour screen will automatically clear in 10 seconds.\n" \
  "Your new PIN is: %s\n"

#define AUTH_LOGIN_PASSWORD_STR \
  "Enter login password: "

// safe prompt function
static int promptUser( const char *prompt, char * buf, const int bufsize )
{
    int i;

    // flush pre-typing if terminal I/O
    //fflush(stdin);

    // tel the user what to do
    printf(prompt);

    // get the response
    if (0 == fgets(buf, bufsize, stdin))
        return 0;

    // remove line ender, two for NT
    i = strlen(buf);
    if (buf[i] < ' ')
        buf[i--] = 0;
    if (buf[i] < ' ')
        buf[i--] = 0;

    return 1;
}

// PIN prompting function
static int promptForPIN( SDI_HANDLE aceHdl, char * buf, const int bufsize, SD_BOOL * bSystemPIN )
{
    SD_PIN      SdPin;
    char        prompt[256];
    char        pinCompare[LENMAXPIN];

    *bSystemPIN = SD_FALSE;

    // retrieve PIN parameters in one call
    AceGetPinParams(aceHdl, &SdPin);

    switch (SdPin.Selectable)
    {
    case CANNOT_CHOOSE_PIN:
        if (promptUser(AUTH_CHALLENGE_NEW_PIN_SYS_STR, buf, bufsize) == 0)
            return 0;

        // did they choose to accept system PIN?
        if (strcmp(buf, "y") == 0)
        {
            strncpy(buf, SdPin.System, bufsize);
            *bSystemPIN = SD_TRUE;
            return 1;
        }
        // force a failure
        return 0;

    case USER_SELECTABLE:
        if (promptUser(AUTH_CHALLENGE_NEW_PIN_STR, buf, bufsize) == 0)
            return 0;

        // did they choose to accept system PIN?
        if (strcmp(buf, "y") == 0)
        {
            strncpy(buf, SdPin.System, bufsize);
            *bSystemPIN = SD_TRUE;
            return 1;
        }
        // let them enter a PIN
        break;

    case MUST_CHOOSE_PIN:
        if (promptUser(AUTH_CHALLENGE_NEW_PIN_USER_STR, buf, bufsize) == 0)
            return 0;

        // did they choose to enter a PIN?
        if (strcmp(buf, "y") != 0)
        {
            // force a failure, did not enter a PIN
            return 0;
        }
        break;
    }

    if (SdPin.Alphanumeric)
    {
		fEcho = 0;
        if (SdPin.Min == SdPin.Max)
            sprintf(prompt, AUTH_CHALLENGE_NEW_PIN_ALPHA_SAME_STR, SdPin.Max);
        else
            sprintf(prompt, AUTH_CHALLENGE_NEW_PIN_ALPHA_STR, SdPin.Min, SdPin.Max);
    }
    else
    {
		fEcho = 0;
        if (SdPin.Min == SdPin.Max)
            sprintf(prompt, AUTH_CHALLENGE_NEW_PIN_DIGITS_SAME_STR, SdPin.Max);
        else
            sprintf(prompt, AUTH_CHALLENGE_NEW_PIN_DIGITS_STR, SdPin.Min, SdPin.Max);
    }
// goto label
Repeat_PIN:
	if(fEcho == 0)
	{
       sd_echo_off();     
       if (promptUser(prompt, buf, bufsize) == 0)
          return 0;
	   printf("\n");
       if (promptUser(AUTH_CHALLENGE_CONFIRM_PIN_STR, pinCompare, sizeof(pinCompare)) == 0)
           return 0;
	   printf("\n");
       sd_echo_on();
	   printf("\n");
	   fEcho = 1;
	}

    if (strcmp(buf, pinCompare) != 0)
    {
        if (promptUser(AUTH_ERROR_CONFIRM_PIN_STR, buf, bufsize) == 0)
            return 0;
		fEcho = 0;
        goto Repeat_PIN;
    }

    return 1;
}

#ifdef WIN32
//Populate the Client IP in network byte order.
void getMyIP(ULONG *clientip)
{
	char hostname[256];
	struct hostent *host;
   
  	gethostname(hostname, sizeof(hostname));
  	host = gethostbyname(hostname);
	*clientip = ( *(unsigned long*)host->h_addr_list[ 0 ] );
	printf("\nClientIP=%d\n",*clientip);
}
#endif

sd_echo_off()
{
#ifdef WIN32
    // get the handle to stdin and the console mode
    hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdIn, &OrigConsoleMode);

    // enable input echo
    ConsoleMode = (OrigConsoleMode& (~ENABLE_ECHO_INPUT |ENABLE_LINE_INPUT)); 
   
	// set consol with no echo
    SetConsoleMode(hStdIn, ConsoleMode);

#endif

#ifndef WIN32
  struct termio sd_echo_sav;
  if (ioctl (0, TCGETA, &sd_echo_sav) == -1)
  {
    printf("can't get orginal settings");
    return(1);
  }

  sd_echo_sav.c_lflag &= ~ECHO;
  if (ioctl(0, TCSETA, &sd_echo_sav) == -1)
  {
    printf("can't initiate new settings");
    return(2);
  }
#endif
}

sd_echo_on()
{
#ifdef WIN32
    // get the handle to stdin and the console mode
    hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdIn, &ConsoleMode);

    // enable input echo
    OrigConsoleMode = (ConsoleMode|ENABLE_ECHO_INPUT|ENABLE_LINE_INPUT);
    
	// reset console to original settings and close handle
    SetConsoleMode(hStdIn, OrigConsoleMode);
#endif

#ifndef WIN32
  struct termio sd_echo_sav;
  if (ioctl (0, TCGETA, &sd_echo_sav) == -1)
  {
    printf("can't get orginal settings");
    return(1);
  }
  sd_echo_sav.c_lflag |= ECHO;
  if (ioctl(0, TCSETA, &sd_echo_sav) == -1)
  {
    printf("can't initiate new settings");
    return(3);
  }
#endif
}

int main(int argc, char *argv[])
{
    SDI_HANDLE SdHdl;
    int ret;
    char * passcodePrompt;
    char username[64], passcode[LENPRNST + 1];
    char pin[LENMAXPIN];
    SD_BOOL bSystemPIN = SD_FALSE;
    char* configPath;
    SD_BOOL bAuth = SD_FALSE;
    int err;
	unsigned long   clientip;

	SD_BOOL bLoginPassword = SD_TRUE;
    SD_BOOL bOfflineAuth = SD_TRUE;
    SD_BOOL bRadiusProfile = SD_TRUE;
    SD_BOOL bRadiusExtension = SD_TRUE;
	

    /* 
     * If the config path is provided at the command line, use it;
     * otherwise, default to the system path. 
     */
    if (argc == 1)
    {
        configPath = NULL;
    }
    else
    {
        configPath = argv[1];
    }

    if (AceInitializeEx(configPath, NULL, 0) == SD_FALSE)
    {
        printf("Failed to initialize ACE API library.\n");
        exit (1);
    }

#ifdef BLD_OFFLINEAUTH
    /*
     * Allows offline auth with local agent.
     */
    if (SD_InitEx(&SdHdl, SD_TRUE, RSA_DA_AGENT_LOCAL) != ACM_OK) /* initialize socket */
    {
        printf("Cannot initialize client-server communications.  \n");
		AceShutdown(NULL);
        exit(1);
    }
#else
	if (SD_Init(&SdHdl) != ACM_OK) /* initialize socket */
    {
        printf("Cannot initialize client-server communications.  \n");
		AceShutdown(NULL);
        exit(1);
    }
#endif

    printf("| Setting Auth Attributes...\n");
    /* Set Auth attributes to Third Party request */
    err = AceSetAuthAttr(SdHdl, 
                         RSA_AUTH_SET_ATTR_RADIUS_PROFILE, 
                         (void*)&bRadiusProfile,
                         sizeof(bRadiusProfile));
    if (err != ACE_SUCCESS) 
    {
        printf("Error setting RADIUS_PROFILE auth attr: %i\n", err);
        bRadiusProfile = SD_FALSE;
    }

    err = AceSetAuthAttr(SdHdl, 
                         RSA_AUTH_SET_ATTR_RADIUS_EXTENSIONS, 
                         (void*)&bRadiusExtension,
                         sizeof(bRadiusExtension));
    if (err != ACE_SUCCESS) 
    {
        printf("Error setting RADIUS_EXTENSIONS auth attr: %i\n", err);
        bRadiusExtension = SD_FALSE;
    }

    /* Set Auth attribute to enable Login-Password Integration */
    err = AceSetAuthAttr(SdHdl, RSA_AUTH_SET_ATTR_LPI, (void*)&bLoginPassword, sizeof(bLoginPassword));
    if (err != ACE_SUCCESS) 
    {
        printf("Error setting LPI auth attr: %i\n", err);
        bLoginPassword = SD_FALSE;
    }

    /* Set Auth attribute to disable Offline-Auth */
    err = AceSetAuthAttr(SdHdl, RSA_AUTH_SET_ATTR_OFFLINE_AUTH, (void*)&bOfflineAuth, sizeof(bOfflineAuth));
    if (err != ACE_SUCCESS) 
    {
        printf("Error setting OA auth attr: %i\n", err);
        bOfflineAuth = SD_FALSE;
    }

    if (0 == promptUser(AUTH_CHALLENGE_USERNAME_STR, username, sizeof(username)) )
    {
        printf("Access denied.\n");
		goto cleanup;
    }
    
    if (strlen(username) == 0)
    {
		goto cleanup;
    }
    
    // default passcode prompt
    passcodePrompt = AUTH_CHALLENGE_PASSCODE_STR;

    // a goto label!!!
NewPinPasscode:    
    ret = SD_Lock(SdHdl, username);
    
    if (ret == ACE_INVALID_ARG)
    {
        printf("ERROR: Invalid username length\n");
		goto cleanup;
    }
    else if (ret == ACE_ERR_INVALID_HANDLE)
    {
        printf("ERROR: Invalid Handle\n");
		goto cleanup;
    }
    else if (ret == ACM_ACCESS_DENIED)
    {
        printf("ERROR: Communication failure\n");
		goto cleanup;
    }
    sd_echo_off();
    if (0 == promptUser(passcodePrompt, passcode, sizeof(passcode)) )
    {
		sd_echo_on();
	    printf("Access denied.\n");
		goto cleanup;
	}
	sd_echo_on();
	printf("\n");
    // default passcode prompt
    passcodePrompt = AUTH_CHALLENGE_PASSCODE_STR;

	// Handling all NEW PIN PARAMETERS
    ret = SD_Check(SdHdl, passcode, username);
    
    switch (ret) 
    { 
    case ACM_OK:
        printf("user %s authenticated \n", username);
        bAuth = SD_TRUE;
        break;
        
    case ACM_ACCESS_DENIED:
        printf("access denied for user %s \n", username);
        break;
        
    case ACM_NEXT_CODE_REQUIRED:
		sd_echo_off();
        if (0 == promptUser(AUTH_CHALLENGE_NEXT_CODE_STR, passcode, sizeof(passcode)) )
        {
			sd_echo_on();
            printf("Access denied.\n");
            break;
        }
		sd_echo_on();
		        
        if (SD_Next(SdHdl, passcode) == ACM_OK)
        {
            printf("Next passcode accepted for user %s \n", username);
            printf("User authenticated \n");
            bAuth = SD_TRUE;
        }
        else
        {
            printf("Access denied, next Tokencode bad \n");
        }
        break;
        
    case ACM_NEW_PIN_REQUIRED:
        if (0 == promptForPIN( SdHdl, pin, sizeof(pin), &bSystemPIN ) )
        {
            SD_Pin(SdHdl, "");  // cancel PIN
            printf("Access denied.\n");
            break;
        }

        // ask the user for PASSCODE again after new PIN is set
        if (SD_Pin(SdHdl, pin) == ACM_NEW_PIN_ACCEPTED)
        {
            // if a system PIN has been set display it
            if (bSystemPIN)
            {
                printf(AUTH_CHALLENGE_NEW_SYS_PIN_DISPLAY_STR, pin);
                // wait for 10 seconds
                sleep(10);
                // clear the screen
                printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
                // make sure display is cleared
                fflush(stdout);
                // clear keystrokes from impatient users
                fflush(stdin);
                passcodePrompt = AUTH_CHALLENGE_NEW_SYS_PIN_PASSCODE_STR;
            }
            else
            {
                passcodePrompt = AUTH_CHALLENGE_NEW_USER_PIN_PASSCODE_STR;
            }
            goto NewPinPasscode;
        }
        SD_Pin(SdHdl, "");  // cancel PIN
        printf("ERROR: New PIN not accepted.\n");
        break;
        
    default:
        printf("unknown return code %d \n", ret);
        printf("Access Denied\n");
    }

	
	//Retrieving extended information
#ifdef WIN32
	err = AceSetCredential(SdHdl, RSA_AUTH_CRED_TYPE_PASSCODE, passcode, sizeof(passcode));
    if (err == ACE_SUCCESS) 
    {
		// Fetching all the data - for which the attributes have been set.
		getMyIP(&clientip);
		sd_echo_off();
		passcodePrompt = AUTH_CHALLENGE_NEW_SYS_PIN_PASSCODE_STR;
		if (0 == promptUser(passcodePrompt, passcode, sizeof(passcode)) )
		{
			sd_echo_on();
			printf("Access denied.\n");
			exit(1);
		}
		sd_echo_on();
		err  = SD_ClientCheck( SdHdl, passcode, username,clientip);

		printf("SD_ClientCheck ret = %d", err);

    }
	else
	{
		printf("Error setting credential: %i\n", err);
		bAuth = SD_FALSE;
	}
    if (err==ACM_OK && bAuth == SD_TRUE)
    {
        SD_CHAR pwBuf[32];
        SD_U32  pwLen = sizeof(pwBuf) - 1;
        SD_CHAR *radProfile = NULL;
        SD_CHAR *radExtension = NULL;
        SD_U32  bufLen = 0;
        char szRealmID[25];
        char minPepper, maxPepper;
        INT32BIT minIterCount, maxIterCount;

        if (bLoginPassword == SD_TRUE)
        {
            err = AceGetLoginPW(SdHdl, pwBuf, &pwLen);
            if (err == ACE_SUCCESS)
            {
                if (pwLen != 0)
                {
                    // Null terminate pwBuf
                    pwBuf[pwLen]= 0;
                    // process the password here;
                }
                else
                {
                    memset(pwBuf, 0, sizeof(pwBuf));
                    if (promptUser(AUTH_LOGIN_PASSWORD_STR, pwBuf, sizeof(pwBuf) - 1) != 0)
                    {
                        err = AceSetLoginPW(SdHdl, pwBuf, strlen(pwBuf));
                        if (err != ACE_SUCCESS) 
                        {
                            printf("Error calling AceSetLoginPW: %i\n", err);
                        }
                    }
                    else
                    {
                        printf("Error reading user's password\n");
                    }
                }
            }
            else
            {
                printf("Error on AceGetLoginPW (%i)\n", err);
            }

            // Clear the password
            memset(pwBuf, 0, sizeof(pwBuf));
        }   // bLoginPassword

        if (bRadiusProfile == SD_TRUE)
        {
            err = AceGetAuthAttr(SdHdl, 
                                 RSA_AUTH_GET_ATTR_RADIUS_PROFILE, 
                                 radProfile, 
                                 &bufLen);
            if (err == ACE_NOT_ENOUGH_STORAGE && bufLen != 0) 
            {
                radProfile = (char*)malloc(bufLen+1);
                if (radProfile != NULL) 
                {
                    /* Actually retrieve RADIUS profile data */
                    err = AceGetAuthAttr(SdHdl, 
                                         RSA_AUTH_GET_ATTR_RADIUS_PROFILE, 
                                         radProfile, 
                                         &bufLen);
                    if (err == ACE_SUCCESS)
                    {
                        /* Null Terminate */
                        radProfile[bufLen] = 0;
                        /* Display RADIUS data */
                        printf("| RADIUS Profile: %s\n", radProfile);
                    }
                    else
                    {
                        printf("Error AceGetAuthAttr on RADIUS attr (%i)\n", err);
                    }
                    free(radProfile);
                }
                else
                {
                  printf("Error allocating radius buffer (size %i)\n", bufLen);
                }
            }
        }   // bRadiusProfile

        if (bRadiusExtension == SD_TRUE)
        {
            bufLen = 0;
            err = AceGetAuthAttr(SdHdl, 
                                 RSA_AUTH_GET_ATTR_RADIUS_EXTENSIONS, 
                                 radExtension, 
                                 &bufLen);
            if (err == ACE_NOT_ENOUGH_STORAGE && bufLen != 0) 
            {
                radExtension = (char*)malloc(bufLen+1);
                if (radExtension != NULL) 
                {
                    /* Actually retrieve RADIUS extension data */
                    err = AceGetAuthAttr(SdHdl, 
                                         RSA_AUTH_GET_ATTR_RADIUS_EXTENSIONS, 
                                         radExtension, 
                                         &bufLen);
                    if (err == ACE_SUCCESS)
                    {
                        /* Null Terminate */
                        radExtension[bufLen] = 0;
                        /* Display RADIUS extension data */
                        printf("| RADIUS EXT: %s\n", radExtension);
                    }
                    else
                    {
                        printf("Error AceGetAuthAttr on RADIUS EXT attr (%i)\n", err);
                    }
                    free(radExtension);
                }
                else
                {
                  printf("Error allocating radius ext buffer (size %i)\n", bufLen);
                }
            }
        }   // bRadiusExtension

        /***********************************************
         * Pull out system policy information
         ***********************************************/

        printf("| System Policy\n");
    
        err = AceGetRealmID(SdHdl, szRealmID);
        if (err!=ACE_SUCCESS) 
        {
            printf("Error AceGetRealmID (%i)\n", err);
        } 
        else
        {
            printf("| - RealmID: '%s'\n", szRealmID);
        }

        err = AceGetIterCountPolicy(SdHdl, &minIterCount, &maxIterCount);
        if (err!=ACE_SUCCESS) 
        {
            printf("Error AceGetIterCountPolicy (%i)\n", err);
        } 
        else
        {
            printf("| - Iteration Count (min/max): %d / %d\n", minIterCount, maxIterCount);
        }

        err = AceGetPepperPolicy(SdHdl, &minPepper, &maxPepper);
        if (err!=ACE_SUCCESS) 
        {
            printf("Error AceGetPepperPolicy (%i)\n", err);
        } 
        else
        {
            printf("| - Pepper (min/max): %d / %d\n", minPepper, maxPepper);
        }


    }   // bAuth
#endif  // Win32

cleanup:
    SD_Close(SdHdl);    /* Shutdown the network connection */

    AceShutdown(NULL);  /* Save the status */

#ifdef WIN32
    CloseHandle(hStdIn);
#endif
    if ( strlen(username) == 0 )
			exit(0);

    if (bAuth != SD_TRUE)
        exit(1);

	return 0;
}

