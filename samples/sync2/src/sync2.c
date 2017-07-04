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
// sync2.c: ACE/Agent synchronous API example
//

// this sample demonstrates the use of SD_Lock, SD_Check, SD_Next, SD_Pin
// it will also demonstrate using the AceGetPinParams function to retrieve
// PIN paramaters in a single call.

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define sleep(x)    Sleep(x*1000)
#define ENABLE_ECHO_INPUT 0x0004
#define ENABLE_LINE_INPUT 0x0002
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <termio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

// in NT this allows using the aceclnt.lib file for linking
#define USE_ACE_AGENT_API_PROTOTYPES
#include "acexport.h"

#ifdef BLD_OFFLINEAUTH
#include "da_svc_api.h"
#endif


int sd_echo_off(void);
int sd_echo_on(void);

#ifdef WIN32
    HANDLE hStdIn;
    DWORD OrigConsoleMode, ConsoleMode;
#endif

int fEcho = 1;

#define MAX_USER_INPUT 256

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

int main( int argc, char * argv[] )
{
    int         acmRet, cTryCount = 0;
    SD_BOOL     bAuthenticated = SD_FALSE;
    SDI_HANDLE  SdiHandle = SDI_HANDLE_NONE;
    SD_BOOL     bSystemPIN = SD_FALSE;
    char        username[MAX_USER_INPUT];
    char        code[MAX_USER_INPUT];
    
#ifdef BLD_OFFLINEAUTH
    acmRet = SD_InitEx(&SdiHandle,1,RSA_DA_AGENT_LOCAL);
#else
	acmRet = SD_Init(&SdiHandle);
#endif

    if (acmRet != ACM_OK)
    {
        printf("Cannot communicate with the ACE/Server. Error = %d\n", acmRet);
        return 1;
    }
    
    // keep trying until authenticated
    cTryCount = 0;
    while (!bAuthenticated && cTryCount < 3)
    {
        // read username
        if (0 == promptUser(AUTH_CHALLENGE_USERNAME_STR, username, sizeof(username)) )
        {
            acmRet = ACM_ACCESS_DENIED;
            printf("Access denied.\n");
            break;
        }
    
        acmRet = SD_Lock(SdiHandle, username);
        if (acmRet != ACM_OK)
        {
            printf("Access denied. Name lock failed.\n");
            break;
        }
        sd_echo_off(); 
        // read user's PASSCODE
        if (0 == promptUser(AUTH_CHALLENGE_PASSCODE_STR, code, sizeof(code)) )
        {
			sd_echo_on();
            acmRet = ACM_ACCESS_DENIED;
            printf("Access denied.\n");
            break;
        }
        sd_echo_on();
        printf("\n");
        acmRet = SD_Check(SdiHandle, code, username);
        switch (acmRet)
        {
        case ACM_OK:                    // we are in now
            printf("Authentication successful.\n");
            bAuthenticated = SD_TRUE;
            break;
            
        case ACM_ACCESS_DENIED:         // not this time
            printf("Access denied.\n");
            cTryCount++;
            break;
            
        case ACM_INVALID_SERVER:
            printf("Invalid server.\n");
            cTryCount++;
            break;
            
        case ACM_NEXT_CODE_REQUIRED:
            // read next token code
            if (0 == promptUser(AUTH_CHALLENGE_NEXT_CODE_STR, code, sizeof(code)) )
            {
                acmRet = ACM_ACCESS_DENIED;
                printf("Access denied.\n");
                cTryCount = 4;  // break loop
                break;
            }

            acmRet = SD_Next(SdiHandle, code);
            if ( acmRet == ACM_OK )
            {
                printf("Authentication successful.\n");
                bAuthenticated = SD_TRUE;
                break;
            }
            
            printf("Access denied.\n");
            cTryCount++;
            break;
            
        case ACM_NEW_PIN_REQUIRED:
            if (0 == promptForPIN( SdiHandle, code, sizeof(code), &bSystemPIN ) )
            {
                SD_Pin(SdiHandle, "");  // cancel PIN
                acmRet = ACM_ACCESS_DENIED;
                printf("Access denied.\n");
                cTryCount = 4;  // break loop
                break;
            }

            acmRet = SD_Pin(SdiHandle, code);
            if (acmRet == ACM_NEW_PIN_ACCEPTED)
            {
                // if a system PIN has been set display it
                if (bSystemPIN)
                {
                    printf(AUTH_CHALLENGE_NEW_SYS_PIN_DISPLAY_STR, code);
                    // wait for 10 seconds
                    sleep(10);
                    // clear the screen
                    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
                    // make sure display is cleared
                    fflush(stdout);
                    // clear keystrokes from impatient users
                    fflush(stdin);
                }
                else
                {
                    printf("New PIN accepted.\n");
                }
                continue;                       // authenticate again now
            }
            
            if (acmRet == ACM_NEW_PIN_REJECTED)
            {
                SD_Pin(SdiHandle, "");  // cancel PIN
                printf("New PIN rejected.\n");
            }
            else  // ACM_ACCESS_DENIED
            {
                SD_Pin(SdiHandle, "");  // cancel PIN
                printf("Access denied.\n");
            }
            break;
            
        default:
            printf("Unexpected error from ACE/Agent API.\n");
            break;
        }  // END OF SWITCH
        
    } // END OF WHILE 
    
    SD_Close(SdiHandle);
	AceShutdown(NULL);
    if (bAuthenticated != SD_TRUE)
        return 1;

#ifdef WIN32
CloseHandle(hStdIn);
#endif
    return 0;
}
