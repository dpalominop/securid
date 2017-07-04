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
*                                                                             *
* File Name: async.c                                                          *
*                                                                             *
*                                                                             *
* Description:  This file demonstrates how to use the new asynchronous        *
*               library to build an interactive authentication agent          *
*               similar to sdshell.                                           *
*                                                                             *
* **** Important Notice ****                                                  *
*                                                                             *
*    This is not a demonstration of a truly asynchronous apoplication.        *
*    If you are using techniques demonstrated here to perform authentication  *
*    you can accomplish the exact same results by using the synchronous API   *
*    as in the example sync2. See the code in the file sync2/src/sync2.c.     *
*                                                                             *
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define sleep(x)    Sleep(x*1000)
#define ENABLE_ECHO_INPUT 0x0004
#define ENABLE_LINE_INPUT 0x0002
#else /* UNIX */
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifndef WIN32
#include <termio.h>
#include <fcntl.h>
#endif

// in NT this allows use of the aceclnt.lib file to link the DLL
#define USE_ACE_AGENT_API_PROTOTYPES
#include "acexport.h"

#ifdef WIN32

typedef HANDLE CONDVAR;
typedef HANDLE MUTEX;

#else

#if !defined(HPUX) || (_POSIX_C_SOURCE - 0 >= 199506L)
#   define COND_TIMEOUT_ERROR(s) ((s) == ETIMEDOUT)
#   define pthread_mutexattr_default NULL
#   define pthread_condattr_default NULL
#else
#   define COND_TIMEOUT_ERROR(s) (((s) != 0) && (errno == EAGAIN))
#endif

#define INFINITE 0
#define WINAPI

typedef unsigned long DWORD;
typedef unsigned long UINT32;
typedef pthread_cond_t CONDVAR;
typedef pthread_mutex_t MUTEX;
typedef void * HANDLE;
#define CALLBACK
#define NO_ERROR 0

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

// a waitable event object
typedef struct
{
    CONDVAR CondVar;    // an event object in NT, a condition variable in UNIX
#ifdef UNIX
    MUTEX Mutex;        // NULL in NT, mutex in UNIX
    int var;            // not used in NT, flag variable in UNIX
#endif
} SDEVENT_S, *P_SDEVENT_S;


// event notification functions
static SD_I32  sdCreateEvent(P_SDEVENT_S);
static void    sdDeleteEvent(P_SDEVENT_S);
static SD_I32  sdWaitForEvent(P_SDEVENT_S, DWORD);
static void    sdSetEvent(P_SDEVENT_S);
static void    sdResetEvent(P_SDEVENT_S);

typedef struct
{
    SDEVENT_S Event;
    int asynchAceRet;
    SDI_HANDLE aceHdl;
    char user[LENUSERNAME+1];
    char prn[LENPRNST+1];
} sEventData;

static void WINAPI aceCB(SDI_HANDLE hdl);

static int Authenticate(void *);

int main()
{
    // Initializes threads 
#ifdef AIX
    pthread_init();
#endif
    
    // AceInitialize is now available and must be called in both Unix and NT
    if (!AceInitialize())
    {
        printf("\nAceInitialize failed\n");
        return 1;
    }
    
    if (Authenticate(0) == ACM_OK)
    {
#ifdef WIN32
    CloseHandle(hStdIn);
#endif
        printf("Authentication successful.\n");
		AceShutdown(NULL);
        return 0;
    }
#ifdef WIN32
    CloseHandle(hStdIn);
#endif
    printf("Authentication failed.\n");
	AceShutdown(NULL);
    return 1;
}

// function where each thread begins execution

#define Thread_Exit(retVal) \
    if (EventData.aceHdl != SDI_HANDLE_NONE) \
    { \
        AceClose(EventData.aceHdl, aceCB); \
        sdWaitForEvent(&EventData.Event, INFINITE); \
		sdDeleteEvent(&EventData.Event); \
    } \
    return (retVal)

static int Authenticate(void * arg)
{
    int retVal;
    sEventData EventData;
    
    memset(&EventData, 0, sizeof(EventData));
    EventData.aceHdl = SDI_HANDLE_NONE;
    
    sdCreateEvent(&EventData.Event);
    
    // init server communication
    
    retVal = AceInit(&EventData.aceHdl,  (void*) &EventData, aceCB);
    if (retVal != ACE_PROCESSING)
    {
        printf("Returned %d\n",retVal);
        Thread_Exit(retVal);
    }
    
    sdWaitForEvent(&EventData.Event, INFINITE);
    
    if ( EventData.asynchAceRet != ACM_OK)
    {
        printf("No response from the ACE/Server.\n");
        retVal = EventData.asynchAceRet;
        Thread_Exit(EventData.asynchAceRet);
    }
    
    if (0 == promptUser(AUTH_CHALLENGE_USERNAME_STR, EventData.user, sizeof(EventData.user)) )
    {
        Thread_Exit(ACM_ACCESS_DENIED);
    }
    
    retVal = AceSetUsername(EventData.aceHdl, EventData.user);
    if (retVal != ACE_SUCCESS)
    {
        Thread_Exit(retVal);
    }
    
    retVal = AceLock(EventData.aceHdl, aceCB);
    
    if (retVal != ACE_PROCESSING)
    {
        Thread_Exit(retVal);
    }
    sdWaitForEvent(&EventData.Event, INFINITE);
    
    if ( EventData.asynchAceRet != ACM_OK)
    {
        printf("No response from the ACE/Server.\n");
        retVal = EventData.asynchAceRet;
        Thread_Exit(EventData.asynchAceRet);
    }
    sd_echo_off();
    if (0 == promptUser(AUTH_CHALLENGE_PASSCODE_STR, EventData.prn, sizeof(EventData.prn)) )
    {
        Thread_Exit(ACM_ACCESS_DENIED);
    }
	sd_echo_on();
	printf("\n");
    retVal = AceSetPasscode(EventData.aceHdl, EventData.prn);
    if (retVal != ACE_SUCCESS)
    {
        Thread_Exit(retVal);
    }
    
    retVal = AceCheck(EventData.aceHdl, aceCB);
    if (retVal != ACE_PROCESSING)
    {
        Thread_Exit(retVal);
    }
    
    sdWaitForEvent(&EventData.Event, INFINITE);
    retVal = EventData.asynchAceRet;
    
    switch (retVal)
    {
    case ACM_OK:  // authentication succeeded
        printf ("ACM_OK for %s\n", EventData.user);
        Thread_Exit(retVal);
        break;
        
    case ACM_ACCESS_DENIED:  // authentication was denied
        printf ("ACM_ACCESS_DENIED for %s\n", EventData.user);
        Thread_Exit(retVal);
        break;
        
    case ACM_NEXT_CODE_REQUIRED: // need next tokencode
		sd_echo_off();
        if (0 == promptUser(AUTH_CHALLENGE_NEXT_CODE_STR, EventData.prn, sizeof(EventData.prn)) )
        {
            Thread_Exit(ACM_ACCESS_DENIED);
        }
        sd_echo_on();
		printf("\n");
        retVal = AceSetNextPasscode(EventData.aceHdl, EventData.prn);
        if (retVal != ACE_SUCCESS)
        {
            Thread_Exit(retVal);
        }
        
        retVal = AceSendNextPasscode(EventData.aceHdl, aceCB);
        if (retVal != ACE_PROCESSING)
        {
            Thread_Exit(retVal);
        }
        
        sdWaitForEvent(&EventData.Event, INFINITE);
        retVal = EventData.asynchAceRet;
        
        if (retVal ==  ACM_OK)  // authentication succeeded
            printf ("ACM_OK for %s\n",EventData.user);
        else
            printf ("ACM_ACCESS_DENIED for %s\n", EventData.user);
        
        Thread_Exit(retVal);
        break;
        
    case ACM_NEW_PIN_REQUIRED:
        {
            SD_BOOL bSystemPIN = SD_FALSE;
            char PIN[LENMAXPIN];

            if ( 0 == promptForPIN( EventData.aceHdl, PIN, sizeof(PIN), &bSystemPIN ) )
            {
                AceCancelPin(EventData.aceHdl, aceCB);
                sdWaitForEvent(&EventData.Event, INFINITE);
                Thread_Exit(ACM_ACCESS_DENIED);
            }
            
            retVal = AceSetPin(EventData.aceHdl, PIN);
            if (retVal != ACE_SUCCESS)
            {
                AceCancelPin(EventData.aceHdl, aceCB);
                sdWaitForEvent(&EventData.Event, INFINITE);
                Thread_Exit(retVal);
            }
            
            retVal = AceSendPin(EventData.aceHdl,  aceCB);
            if (retVal != ACE_PROCESSING)
            {
                AceCancelPin(EventData.aceHdl, aceCB);
                sdWaitForEvent(&EventData.Event, INFINITE);
                Thread_Exit(retVal);
            }
            
            sdWaitForEvent(&EventData.Event, INFINITE);
            retVal = EventData.asynchAceRet;
            
            if ( retVal != ACM_NEW_PIN_ACCEPTED)
            {
                printf("Failed to set new PIN.\n");
                Thread_Exit(retVal);
            }

            // if a system PIN has been set display it
            if (bSystemPIN)
            {
                printf(AUTH_CHALLENGE_NEW_SYS_PIN_DISPLAY_STR, PIN);
                // wait for 10 seconds
                sleep(10);
                // clear the screen
                printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
                // make sure display is cleared
                fflush(stdout);
                // clear keystrokes from impatient users
                fflush(stdin);
            }
            // lock the username to ask for passcode again
            retVal = AceLock(EventData.aceHdl, aceCB);
            
            if (retVal != ACE_PROCESSING)
            {
                Thread_Exit(retVal);
            }
            sdWaitForEvent(&EventData.Event, INFINITE);
            
			sd_echo_off();
            if (0 == promptUser(AUTH_CHALLENGE_NEW_SYS_PIN_PASSCODE_STR, EventData.prn, sizeof(EventData.prn)) )
            {
                Thread_Exit(ACM_ACCESS_DENIED);
            }
            sd_echo_on();
			printf("\n");

            retVal = AceSetPasscode(EventData.aceHdl, EventData.prn);
            if (retVal != ACE_SUCCESS)
            {
                Thread_Exit(retVal);
            }
            
            retVal = AceCheck(EventData.aceHdl, aceCB);
            if (retVal != ACE_PROCESSING)
            {
                Thread_Exit(retVal);
            }
            
            sdWaitForEvent(&EventData.Event, INFINITE);
            
            if (EventData.asynchAceRet == ACM_OK)
                printf ("ACM_OK for %s\n", EventData.user);
            else
                printf ("ACM_ACCESS_DENIED for %s\n", EventData.user);
            
            retVal = EventData.asynchAceRet;
            Thread_Exit(retVal);
            
            break;
        }
        
    default:
        break;
    }     

    retVal = EventData.asynchAceRet;
	sdDeleteEvent(&EventData.Event);
    Thread_Exit(retVal);
}

static void WINAPI aceCB(SDI_HANDLE hdl)
{
    sEventData *proc;
    
    if(AceGetUserData(hdl, (void**) &proc) != ACE_SUCCESS)
        printf("\n AceGetUserData failed..\n");
    
    if(AceGetAuthenticationStatus(hdl,(INT32BIT *) &proc->asynchAceRet) != ACE_SUCCESS)
        printf("\n GetAuthenticationStatus failed...\n");
    
    sdSetEvent(&proc->Event);
}

static SD_I32 sdCreateEvent(P_SDEVENT_S Event)
{
#ifdef WIN32
    // create an EVENT_S object specific to this authentication request
    Event->CondVar = CreateEvent(NULL, SD_FALSE, SD_FALSE, NULL);
    if (! Event->CondVar)
    {
        return ACE_EVENT_CREATE_FAIL;
    }
#endif
#ifdef UNIX
    // create condition variable specific to this request
    if (pthread_cond_init(&Event->CondVar,
        pthread_condattr_default) != 0)
    {
        return ACE_PTHREADCONDVAR_CREATE_FAIL;
    }
    
    // create mutex specific to this request
    if (pthread_mutex_init(&Event->Mutex,
        pthread_mutexattr_default) != 0)
    {
        return ACE_PTHREADMUTEX_CREATE_FAIL;
    }
    // set event to not signaled at creation
    Event->var = 0;
#endif
    return 0;
}

static void sdDeleteEvent(P_SDEVENT_S Event)
{
#ifdef UNIX
    pthread_cond_destroy(&Event->CondVar);
    pthread_mutex_destroy(&Event->Mutex);
#endif
#ifdef WIN32
    if (Event->CondVar)
        CloseHandle(Event->CondVar);
#endif
}

static SD_I32 sdWaitForEvent(P_SDEVENT_S Event, DWORD ms)
{
#ifdef WIN32
    return (WaitForSingleObject(Event->CondVar, ms));
#endif
    
#ifdef UNIX
    
    int ret = NO_ERROR;
    
    if (pthread_mutex_lock(&Event->Mutex) != 0)
    {
        return 1;
    }
    // if INFINITE timeout then wait for ever
    if (INFINITE == ms)
    {
        // did the event get cleared?
        while (! Event->var)
        {
            // always wait until the flag is clear
            ret = pthread_cond_wait(&Event->CondVar, &Event->Mutex);
            if (ret == NO_ERROR)
            {
                break;
            }
        }
        // clear event always
        Event->var = 0;
    }
    // wait until the timeout time
    else
    {
        
#define MILLISEC_PER_SEC       1000L
#define NANOSEC_PER_MILLISEC   1000000L
#define NANOSEC_PER_SEC        1000000000L
        
        struct timespec delta, timeout;
        struct timeval now;
        struct timezone tz;

		// get current time
        gettimeofday(&now, &tz);
        // calculate the delta used for timeout
        delta.tv_sec = ms / MILLISEC_PER_SEC;
        delta.tv_nsec = (ms % MILLISEC_PER_SEC) * NANOSEC_PER_MILLISEC;
        // get timeout for timed wait
        timeout.tv_sec = now.tv_sec + delta.tv_sec;
        timeout.tv_nsec = (now.tv_usec * 1000) + delta.tv_nsec;
        // if more than a second
        if (timeout.tv_nsec > NANOSEC_PER_SEC)
        {
            timeout.tv_sec ++;              // bump up by one second
			timeout.tv_nsec -= NANOSEC_PER_SEC;
        }
    
        // wait until condition or timeout
        while (! Event->var)
        {
            ret = pthread_cond_timedwait(&Event->CondVar, &Event->Mutex, &timeout);
            // success, or timeout
            if ((ret == 0) || COND_TIMEOUT_ERROR(ret))
            {
                break;
            }
        }
        // success, clear event
        if (ret == NO_ERROR)
        {
            Event->var = 0;
        }
    }
    
    pthread_mutex_unlock(&Event->Mutex);
    
    return ret;
    
#endif
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
// sdSetEvent
//   This function sets an event object to the signalled state.
//   On UNIX, we used a mutex and a condition variable to "build"
//   the event object.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static void sdSetEvent(P_SDEVENT_S Event)
{
#ifdef WIN32
    SetEvent(Event->CondVar);
#endif
    
#ifdef UNIX
    int ret;
    if ((ret = pthread_mutex_lock(&Event->Mutex)) != 0)
    {
        printf("\n pthread_mutex_lock return %d\n", ret);
        return;
    }
    
    Event->var = 1;
    if (pthread_cond_signal(&Event->CondVar) != 0)
    {
        return;
    }
    if (pthread_mutex_unlock(&Event->Mutex) != 0)
    {
        return;
    }
    
#endif
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
// sdResetEvent
//   This function resets an event object to the non-signalled state.
//   On UNIX, we used a mutex and a condition variable to "build"
//   the event object.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static void sdResetEvent(P_SDEVENT_S Event)
{
#ifdef WIN32
    ResetEvent(Event->CondVar);
#endif
    
#ifdef UNIX
    if (pthread_mutex_lock(&Event->Mutex) != 0)
    {
        return;
    }
    Event->var = 0;
    if (pthread_mutex_unlock(&Event->Mutex) != 0)
    {
        return;
    }
    
#endif
}

