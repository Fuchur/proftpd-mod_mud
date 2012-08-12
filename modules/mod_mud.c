/*
 * mod_mud.c: mud-user login&file access handling
 *
 * @author Fuchur@Wunderland
 * @author Holger@Wunderland
 * @author Wolfgang Hamann, wolfgang@blitzstrahl
 * @author Tiamak@MorgenGrauen
 * @author Matthias L. Jugel, MorgenGrauen
 * @author Peng@FinalFrontier (original)
 *
 * v1.7
 */

#include "conf.h"

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif
 
#include "privs.h"

#include "mud.h"


#define MU_AUTH_INTERNAL   1
#define MU_AUTHENTICATED   2

#define MODE_READ          1
#define MODE_WRITE         2
#define MODE_LIST          4

#if 0
#undef int core_display_file
extern int core_display_file(const char *,const char *);
#endif

extern module auth_module;
static int    udp_socket;           /* Our udp socket, -1 if inactive */
static long   udp_seqnumber;        /* The message id-number */
static struct sockaddr_in gd_addr;  /* The address of the gamedriver */
static int    udp_portno = 0;
static int    udp_retries = UDP_RETRIES;
static int    udp_delay = UDP_DELAY;
static int    mud_login = 0;        /* mud-user or 'real' user? */
static char   *muduser;
static struct group *mudgroup;
static struct passwd *muduserpw;    /* it is used for further use of the
                                       muduser data */
module mud_module;


/* Declarations */

static int mud_sess_init();
static char *sgetsave(char *);
static int get_msg ( char *, char **, int );
static int send_msg ( char **, char *, char *, char *, char * );
static struct mudpw *getmudpw( char * );
#if 0
static void build_group_arrays( pool *, struct passwd *, char *,
                                array_header **, array_header ** );
#endif
static int mud_setup_environment( pool *, char *, char * );
static int mud_verify_access( char *, int );
static char *mud_getdir( cmd_rec * );

MODRET mud_set_udpport( cmd_rec * );
MODRET mud_set_pathmudlib( cmd_rec * );
MODRET pw_auth( cmd_rec * );
MODRET mud_cmd_pass( cmd_rec * );
MODRET mud_cmd_read( cmd_rec * );
MODRET mud_cmd_write( cmd_rec * );


static int mud_sess_init()
{
    struct group *grp = NULL;
    struct passwd *pw = NULL;
    char *mudgroupname = NULL;
    int *udp_portno_ptr;

    muduser = (char *)get_param_ptr( main_server->conf, "MudUserName", FALSE );
    mudgroupname = (char *)get_param_ptr( main_server->conf, "MudGroupName",
                                          FALSE );

    udp_portno_ptr = get_param_ptr( main_server->conf, "UDPPortno", FALSE );
    udp_portno = udp_portno_ptr ? *udp_portno_ptr : 0;
 
    if ( udp_portno < 1024 ){
        pr_log_debug( DEBUG1, "mod_mud: UDPPortno must be set.");
        end_login(1);
        return 0;
    }

    if ( (pw = getpwnam(muduser)) == NULL){
        endpwent();
        pr_response_add_err( R_451, "Internal server error, giving up." ); 
        end_login(1);
        return 0;
    }

    if ( (muduserpw = malloc(sizeof (struct passwd))) != NULL )
        memcpy( muduserpw, pw, sizeof(struct passwd) );
    else{
        pr_response_add_err( R_451, "Internal server error, giving up." );
        end_login(1);
        return 0;
    }

    if ( (grp = getgrnam(mudgroupname)) == NULL ){
        endgrent();
        pr_response_add_err( R_451, "Internal server error, giving up." );
        end_login(1);
        return 0;
    }

    if ( (mudgroup = malloc(sizeof (struct group))) != NULL )
        memcpy( mudgroup, grp, sizeof(struct group) );
    else{
        pr_response_add_err( R_451, "Internal server error, giving up." );
        end_login(1);
        return 0;
    }

    udp_socket = -1;
    
    memset( (char *)&gd_addr, 0, sizeof(gd_addr) );
    gd_addr.sin_family = AF_INET;
    gd_addr.sin_addr = *(struct in_addr *)pr_netaddr_get_inaddr(session.c->local_addr);
    gd_addr.sin_port = htons(udp_portno);
    udp_seqnumber = 0;

    if ( (udp_socket = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 ){
        pr_log_debug( DEBUG1,
                   "mod_mud: Cannot open and receive socket for UDP-Mode." );
        end_login(1);
    }

  return 0;
}


static char *sgetsave(char *s)
{
    char *new = (char *)malloc( (unsigned) strlen(s) + 1 );
  
    if ( new == NULL ){
         pr_response_add_err( R_421, "Local resource failure: malloc." );
        end_login(1);
        /* NOTREACHED */
    }
    (void) strcpy( new, s );
    return (new);
}


static int get_msg ( char *type, char **result, int quick )
{
    int retries, discard, rc, tlen;
    socklen_t fromlen;
    struct timeval timeout;
    fd_set readfds;
    struct sockaddr_in from_addr;
    char buf[8192], *rest;

    if ( udp_socket < 0 ){
        pr_log_debug( DEBUG1, "mod_mud: get_msg() called w/o socket" );
        return -1;
    }

    tlen = strlen(type);
    retries = quick ? 1 : udp_retries;
    discard = (retries ? retries : 1);
    *result = NULL;

    while ( retries >= 0 && discard > 0 ){
        timeout.tv_sec  = udp_delay;
        timeout.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET( udp_socket, &readfds );
        rc = select( NFDBITS, &readfds, NULL, NULL, &timeout );
        
        if ( rc <= 0 || !FD_ISSET(udp_socket, &readfds) ){
            /* Timeout or Error */
            if ( rc < 0 )
                pr_log_debug( DEBUG1, "mod_mud: select() on upd socket: %m" );
            else {
                if (!rc)
                    pr_log_debug( DEBUG5, "mod_mud: select() timed out" );
                else if ( !FD_ISSET(udp_socket, &readfds) )
                    pr_log_debug( DEBUG5, "mod_mud: udp_socket not ready" );
            }
            
            retries--;
            continue;
        }

        fromlen = sizeof(from_addr);
        rc = recvfrom( udp_socket, buf, 8192, 0, (struct sockaddr *)&from_addr,
                       &fromlen );
        if ( rc <= 0 ){
            if ( rc < 0 )
                pr_log_debug( DEBUG1, "mod_mud: recvfrom() failed: %m" );
            else
                pr_log_debug( DEBUG1, "mod_mud: recvfrom() received nothing" );
            retries--;
            continue;
        }
        
        if ( rc < 8192 )
            buf[rc] = '\0';

        if ( memcmp( &from_addr.sin_addr, &gd_addr.sin_addr,
                     sizeof(gd_addr.sin_addr) ) ){
            pr_log_debug( DEBUG1, "mod_mud: Packet from %s:%hd ignored",
                       inet_ntoa(from_addr.sin_addr), from_addr.sin_port );
            retries--;
            continue;
        }

        pr_log_debug( DEBUG1, "mod_mud: get_msg(): recvd |%s|", buf );

        if ( strncasecmp( buf, "NFTPD\t", 6 )
             || udp_seqnumber != strtol( buf+6, &rest, 10 )
             || rest == NULL
             || strncasecmp( rest, "\tRPLY\t", 6 )
             || strncasecmp( rest+6, type, tlen )
             || (rest[6+tlen] != '\0' && rest[6+tlen] != '\t') ){
            pr_log_debug( DEBUG1, "mod_mud: Packet |%s| ignored", buf );
            discard--;
            continue;
        }

        rest += 6+tlen;
        if (*rest == '\t')
            rest++;
        *result = sgetsave(rest);
        return 0;
    }

    pr_log_debug( DEBUG1, "mod_mud: get_msg() gives up" );

    return -1;
}


/* Send a message "<type>\t<arg1>\t<arg2>\t<arg3>" (if that much args are 
 * given) to the LPMud and wait for a matching answer.
 * If a matching answer was received, its content part is copied in a 
 * freshly allocated string, which is returned as <result> (it is at least 
 * the empty string).
 * Direct result is 0 on success, -1 on failure.
 */

static int send_msg ( char **result, char *type, char *arg1, char *arg2,
                      char *arg3 )
{
    char buf[8192];
    int retries, rc, len;
    
    if ( udp_socket < 0 ){
        pr_log_debug( DEBUG1, "mod_mud: send_msg() called w/o socket" );
        return -1;
    }

    ++udp_seqnumber;
    sprintf( buf, "NFTPD\t%ld\tREQ\t%s", udp_seqnumber, type );
    if ( NULL != arg1 ){
        strcat( buf, "\t" );
        strcat( buf, arg1 );
    }
    if ( NULL != arg2 ){
        strcat( buf, "\t" );
        strcat( buf, arg2 );
    }
    if ( NULL != arg3 ){
        strcat( buf, "\t" );
        strcat( buf, arg3 );
    }
    
    len = strlen(buf);

    if ( strncmp( type, "PASS", 4 ) )
        pr_log_debug( DEBUG4, "mod_mud: send_msg(): sending |%s|", buf );

    for ( retries = udp_retries; retries > 0; retries--){
        rc = sendto( udp_socket, buf, len, 0, (struct sockaddr *)&gd_addr,
                     sizeof(gd_addr));
        if ( rc != len ){
            if ( rc < 0 )
                pr_log_debug( DEBUG1, "mod_mud: sendto() failed:%m" );
            else
                pr_log_debug( DEBUG5, "mod_mud: sendto() sent %d of %d byte",
                           rc, len );
            continue;
        }
        
        if ( !get_msg( type, result, 1 ) )
            return 0;
    }

    pr_log_debug( DEBUG1, "mod_mud: send_msg() gives up" );

    return -1;
}


static struct mudpw *getmudpw( char *name )
{
    struct mudpw *save;
    char *result;
  
    if ( (save = (struct mudpw *) malloc(sizeof(struct mudpw))) == NULL )
        return (struct mudpw *)0;
    if ( NULL == (save->pw.pw_name = (char *)malloc(15)) )
        return (struct mudpw *)0;
    if ( NULL == (save->pw.pw_passwd = (char *)malloc(26)) )
        return (struct mudpw *)0;
    if ( NULL == (save->pw.pw_dir = (char *)malloc(MAXPATHLEN+1)) )
        return (struct mudpw *)0;
    if ( NULL == (save->pw.pw_gecos = (char *)malloc(1)) )
        return (struct mudpw *)0;
    save->pw.pw_shell = NULL;
    save->pw_level = -1;
  
    strcpy( save->pw.pw_name, name );

    if ( !send_msg( &result, "USER", name, NULL, NULL) ){
        if ( !strncasecmp( "NONE", result, 4 ) ){
            pr_log_debug( DEBUG1, "mod_mud: getmudpw(%s) rejected by udp", name );
            free(result);
            return NULL;
        }
        
        strcpy( save->pw_rdir, result );
        strcpy( save->pw.pw_dir, save->pw_rdir );
        strcpy( save->pw.pw_passwd, "dummy" );
        free(result);
        return save;
    }
    
    pr_log_debug( DEBUG1, "mod_mud: getmudpw(): no udp connection" );
    
    udp_socket = -1;

    return NULL;
}


#if 0
static void build_group_arrays( pool *p, struct passwd *xpw, char *name,
                                array_header **gids, array_header **groups )
{
    struct group *gr;
    struct passwd *pw = xpw;
    array_header *xgids, *xgroups;
    char **gr_mem;

    xgids = make_array( p, 2, sizeof(int) );
    xgroups = make_array( p, 2, sizeof(char*) );

    if ( !pw && !name ){
        *gids = xgids;
        *groups = xgroups;
        return;
    }

    if ( !pw ){
        pw = auth_getpwnam( p, name );

        if ( !pw ){
            *gids = xgids;
            *groups = xgroups;
            return;
        }
    }

    if ( (gr = auth_getgrgid( p, pw->pw_gid )) != NULL )
        *((char**) push_array(xgroups)) = pstrdup( p, gr->gr_name );

    auth_setgrent(p);

    while ( (gr = auth_getgrent(p)) != NULL && gr->gr_mem )
        for ( gr_mem = gr->gr_mem; *gr_mem; gr_mem++ ){
            if ( !strcmp( *gr_mem, pw->pw_name ) ){
                *((int*) push_array(xgids)) = (int) gr->gr_gid;
                
                if ( pw->pw_gid != gr->gr_gid )
                    *((char**) push_array(xgroups)) = pstrdup( p, gr->gr_name );
                break;
            }
        }

    *gids = xgids;
    *groups = xgroups;
}
#endif

// at this point, unix passwords have gone
static void build_dummy_group_arrays( pool *p, struct passwd *xpw, char *name,
                                array_header **gids, array_header **groups )
{
    struct passwd *pw = xpw;
    array_header *xgids, *xgroups;

    xgids = make_array( p, 2, sizeof(int) );
    xgroups = make_array( p, 2, sizeof(char*) );

    if ( !pw && !name ){
        *gids = xgids;
        *groups = xgroups;
        return;
    }

	*((int*) push_array(xgids)) = 300;
	*((char**) push_array(xgroups)) = pstrdup( p, "games" );

    *gids = xgids;
    *groups = xgroups;
}


static int mud_setup_environment( pool *p, char *user, char *pass )
{
    struct mudpw *pw;
    struct stat sbuf;
    char *defroot = NULL;
    int authcode = 0;

    /********************* Authenticate the user here *********************/

    session.hide_password = TRUE;

    if ( (pw = getmudpw(user)) == NULL ){
        log_pri( LOG_NOTICE, "mod_mud: failed login, can't find user '%s'",
                 user );
        return 0;
    }

    authcode = pr_auth_authenticate( p, user, pass );

    session.user = pstrdup( p, user );
    session.group = pstrdup( p, mudgroup->gr_name );

    switch(authcode){
    case PR_AUTH_NOPWD:
        log_auth( LOG_NOTICE,
                  "mod_mud: USER %s: no such user found from %s [%s] to %s:%i",
                  user, session.c->remote_name,
					pr_netaddr_get_ipstr(session.c->remote_addr),
					pr_netaddr_get_ipstr(session.c->local_addr),
                  session.c->local_port );
        break;
        
    case PR_AUTH_BADPWD:
        log_auth( LOG_NOTICE,
                  "mod_mud: USER %s: incorrect password from %s [%s] to %s:%i",
                  user, session.c->remote_name,
                    pr_netaddr_get_ipstr(session.c->remote_addr),
                    pr_netaddr_get_ipstr(session.c->local_addr),
                  session.c->local_port );
        break;
    };

    if ( authcode != 0 || !(mud_login & MU_AUTHENTICATED) )
        return 0;
    
    strncpy( session.cwd, pw->pw.pw_dir, PR_TUNABLE_PATH_MAX );

    log_auth( LOG_NOTICE, "mod_mud: FTP login as '%s' from %s [%s] to %s:%i",
              user, session.c->remote_name,
                    pr_netaddr_get_ipstr(session.c->remote_addr),
                    pr_netaddr_get_ipstr(session.c->local_addr),
              session.c->local_port );
    
    /* Now check to see if the user has an applicable DefaultRoot */
    if ( (defroot = get_param_ptr( main_server->conf, "PathMudlib", FALSE ))
         != NULL ){

        PRIVS_ROOT;

        if ( chroot(defroot) == -1 ){

            PRIVS_RELINQUISH;

         pr_response_add_err( R_530, "Unable to set default root directory." );

            log_pri( LOG_ERR, "mod_mud: %s chroot(\"%s\"): %s", session.user,
                     defroot, strerror(errno) );
            end_login(1);
        }

        PRIVS_RELINQUISH;
    }
    else{
         pr_response_add_err( R_530, "Mud root directory is not seT." ); 

        log_pri( LOG_ERR, "mod_mud: %s mud-chroot(\"%s\"): %s", session.user,
                 defroot, strerror(errno) );
        end_login(1);
    }
  
    /* new in 1.1.x, I gave in and we don't give up root permanently..
     * sigh.
     */

    pr_signals_block();

    PRIVS_ROOT;

    setuid(0);
    setgid(0);

    PRIVS_SETUP( muduserpw->pw_uid, muduserpw->pw_gid )

        pr_signals_unblock();

#ifdef HAVE_GETEUID
    if( getegid() != muduserpw->pw_gid || geteuid() != muduserpw->pw_uid ){
        
        PRIVS_RELINQUISH;

        pr_response_add_err( R_530, "Unable to set user privileges." );
        log_pri( LOG_ERR, "mod_mud: %s setregid() or setreuid(): %s",
                 session.user, strerror(errno) );

        end_login(1);
    }
#endif

    /* chdir to the proper directory, do this even if anonymous
     * to make sure we aren't outside our chrooted space.
     */

    if ( pr_fsio_chdir_canon( session.cwd, 1 ) == -1 ){
        pr_response_add_err( R_530, "Unable to chdir." );
        log_pri( LOG_ERR, "mod_mud: %s chdir(\"%s\"): %s", session.user,
                 session.cwd, strerror(errno) );
        end_login(1);
    }
    
    strncpy( session.cwd, pr_fs_getcwd(), sizeof(session.cwd) );
    strncpy( session.vwd, pr_fs_getvwd(), sizeof(session.vwd) );

    /* check dynamic configuration */
    if ( pr_fsio_stat( "/", &sbuf ) != -1 )
        build_dyn_config( p, "/", &sbuf, 1 );

    session.proc_prefix = pstrdup( permanent_pool, session.c->remote_name );
    session.sf_flags = 0;

    /* Default transfer mode is ASCII */
    session.sf_flags |= SF_ASCII;
 
    /* Authentication complete, user logged in */

//  pr_scoreboard_update_entry(getpid(),
//    PR_SCORE_USER, session.user,
//    PR_SCORE_CWD, session.cwd,
//    NULL);

//    log_run_address( session.c->remote_name, session.c->remote_ipaddr );
//    log_run_cwd(session.cwd);
    session_set_idle();
    pr_timer_remove( PR_TIMER_LOGIN, &auth_module );

    session.user = pstrdup(permanent_pool,session.user);

    if (session.group)
      session.group = pstrdup(permanent_pool,session.group);
     pr_log_debug( DEBUG1, "mod_mud: make groups." );
#if 1
//    build_group_arrays( session.pool, &pw->pw, NULL,
//                        &session.gids, &session.groups );
    build_dummy_group_arrays( session.pool, &pw->pw, NULL,
                        &session.gids, &session.groups );
#else
    if (session.gids)
      session.gids = copy_array(permanent_pool, session.gids);

    /* session.groups is an array of strings, so we must copy the string data
     * as well as the pointers.
     */
    session.groups = copy_array_str(permanent_pool, session.groups);
  
    /* Resolve any deferred-resolution paths in the FS layer */
    pr_resolve_fs_map();
#endif
   pr_log_debug( DEBUG1, "mod_mud: end setup." );
    return 1;
}


/* Verify access rights fo a given file. */

static int mud_verify_access( char *dir, int modus )
{
    char *mode = NULL, *result;

    if ( modus < MODE_READ || modus > MODE_LIST )
        return 0;

    switch ( modus ){
    case MODE_READ:
        mode = "READ";
        break;

    case MODE_WRITE:
        mode = "WRIT";
        break;

    case MODE_LIST:
        mode = "LIST";
        break;
    }
        
    if ( !send_msg( &result, mode, session.user, dir, NULL ) ){
        if ( !strncasecmp( "FAIL", result, 4 ) ){
            pr_response_add_err( R_550, " %s: Permission denied.", dir );  
            free(result);
            return 0;
        }
        
        if ( !strncasecmp( "OK", result, 2 ) ){
            free(result);
            return 1;
        }
        else {
            pr_log_debug( DEBUG1, "mod_mud: Got invalid values from mud: %s",
                       result );
            
            pr_response_add_err( R_451,
                              " External process not working, giving up." );
            end_login(1);
            return 0;
        }
    }

    pr_log_debug( DEBUG1, "mod_mud: No udp connection established." );
    pr_response_add_err( R_451, " Cannot verify your rights, giving up." );

    udp_socket = -1;
    end_login(1);
    return 0;
}
  

static char *mud_getdir( cmd_rec *cmd )
{
    static char target[MAXPATHLEN];
    char *dir, *user;

    if ( cmd->argc == 1 )
        dir = ".";
    else
        dir = cmd->arg;

    if ( !strncmp( dir, "+", 1 ) ){
        strncpy( target, "/d/", 4 );
        strncat( target, dir+1, MAXPATHLEN-2 );
        target[MAXPATHLEN-1] = 0;
        dir = target;
        cmd->arg = target;
    }
    else if ( !strncmp( dir, "~/", 2 ) ){
        strncpy( target, "/players/", 10 );
        user = (char*)get_param_ptr( cmd->server->conf, C_USER, FALSE );
        strcat( target, user );
        strncat( target, dir+1, MAXPATHLEN-strlen(user)-8 );
        target[MAXPATHLEN-1] = 0;
        dir = target;
        cmd->arg = target;
    }
    else if ( !strncmp( dir, "~", 1 ) ){
        strncpy( target, "/players/", 10 );
        strncat( target, dir+1, MAXPATHLEN-8 );
        target[MAXPATHLEN-1] = 0;
        dir = target;
        cmd->arg = target;
    }
    
    dir_interpolate( cmd->tmp_pool, dir );
    dir = dir_best_path( cmd->tmp_pool, dir );

    return dir;
}


MODRET mud_set_udpport( cmd_rec *cmd )
{
    int portno;
    int *portno_ptr;
    
    CHECK_ARGS( cmd, 1 );
    CHECK_CONF( cmd, CONF_ROOT|CONF_GLOBAL );
    portno = atoi(cmd->argv[1]);
    
    if ( portno < 1024 )
        CONF_ERROR( cmd, "UDPPortno must be greater than 1024." );

    if (NULL == (portno_ptr = pcalloc(main_server->pool, sizeof(int))))
        return ERROR(cmd);

    *portno_ptr = portno;

    add_config_param( "UDPPortno", 1, (void *)portno_ptr );
    udp_portno = portno;
    
    return HANDLED(cmd);
}


MODRET mud_set_pathmudlib( cmd_rec *cmd )
{
    char *dir;

    CHECK_CONF( cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL );
    CHECK_ARGS( cmd, 1 );

    dir = cmd->argv[1];

    /* dir must be '/'
     */

    if ( *dir != '/' )
        CONF_ERROR( cmd, pstrcat( cmd->tmp_pool, "(", dir,
                                  ") absolute pathname required.", NULL ) );

    if ( strchr( dir, '*' ) )
        CONF_ERROR( cmd, pstrcat( cmd->tmp_pool, "(", dir,
                                  ") wildcards not allowed in pathname." ) );

    if ( *(dir + strlen(dir) - 1) == '/' )
        CONF_ERROR( cmd, pstrcat( cmd->tmp_pool,
                                  "no / allowed at end of ", dir ) );

    add_config_param_str( "PathMudlib", 1, dir );

    return HANDLED(cmd);
}

MODRET mud_set_muduser( cmd_rec *cmd )
{	char *user;

    CHECK_CONF( cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL );
    CHECK_ARGS( cmd, 1 );

    user = cmd->argv[1];

    add_config_param_str( "MudUserName", 1, user );

    return HANDLED(cmd);
}

MODRET mud_set_mudgroup( cmd_rec *cmd )
{	char *group;

    CHECK_CONF( cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL );
    CHECK_ARGS( cmd, 1 );

    group = cmd->argv[1];

    add_config_param_str( "MudGroupName", 1, group );

    return HANDLED(cmd);
}


MODRET pw_auth( cmd_rec *cmd )
{
    char *result;
    const char *name;
    const char *clearpw;

    name = cmd->argv[0];
    clearpw = cmd->argv[1];

    if ( !(mud_login & MU_AUTH_INTERNAL) )
        /* shortcut */
        return DECLINED(cmd);
 
    if ( !send_msg( &result, "PASS", (char *)name, (char *)clearpw, NULL ) ){
        if ( !strncasecmp( result, "OK", 2 ) ){
            free(result);
            /* mud-user identified */
            mud_login |= MU_AUTHENTICATED;
            return HANDLED(cmd);
        }
            
        pr_log_debug( DEBUG1, "mod_mud: auth pw(%s) rejected by udp", name );
        free(result);
        return DECLINED(cmd);
    }
    
    pr_log_debug( DEBUG1, "mod_mud: pw_auth(): no udp connection" );

    return DECLINED(cmd);
}


MODRET mud_cmd_pass( cmd_rec *cmd )
{
    char *display = NULL;
    char *user, *grantmsg;
	unsigned char *authenticated;
    config_rec *c = NULL;
    int res = 0;

	authenticated = get_param_ptr(main_server->conf, "authenticated", FALSE);
    if (authenticated && (*authenticated != FALSE))
        return ERROR_MSG( cmd, R_503, "You are already logged in!" );

    user = (char*)get_param_ptr( cmd->server->conf, C_USER, FALSE );

    if ( !user )
        return ERROR_MSG( cmd, R_503, "Login with USER first." );

    /* shortcut for pw_auth */
    mud_login |= MU_AUTH_INTERNAL;
    
    if ( (res = mud_setup_environment( cmd->tmp_pool, user, cmd->arg )) ){
	    c = add_config_param_set(&cmd->server->conf, "authenticated", 1, NULL);
 	   c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
	    *((unsigned char *) c->argv[0]) = TRUE;

	    set_auth_check(NULL);
        display = (char*)get_param_ptr( cmd->server->conf, "DisplayLogin",
                                        FALSE );

        if ( display )
            pr_display_file( R_230, display, NULL );

        if ( (grantmsg = (char*)get_param_ptr( cmd->server->conf,
                                               "AccessGrantMsg", FALSE) )
             != NULL){
            grantmsg = sreplace( cmd->tmp_pool, grantmsg, "%u", user, NULL );
            pr_response_add( R_230, "%s", grantmsg );
        } 
        else
            pr_response_add( R_230, "User %s logged in.", user );
        return HANDLED(cmd);
    }

    /* user is not a mud-user. try external identification */
    mud_login &= ~MU_AUTH_INTERNAL;
    
    return DECLINED(cmd);
}


MODRET mud_cmd_read( cmd_rec *cmd )
{
    char *dir = NULL;
    
    if ( !(mud_login & MU_AUTHENTICATED) )
        /* not our job */
        return DECLINED(cmd);
    
    pr_log_debug( DEBUG5, "mod_mud: mud_cmd_read" );

    if ( (dir = mud_getdir(cmd)) == NULL ){
        pr_response_add_err( R_550, "Could not resolve '%s'.", cmd->arg );
        return ERROR(cmd);
    }

    if ( !mud_verify_access(dir, MODE_READ) )
        return ERROR(cmd);
  
    return DECLINED(cmd);
}


MODRET mud_cmd_write( cmd_rec *cmd )
{
    char *dir = NULL;

    if ( !(mud_login & MU_AUTHENTICATED) )
        /* not our job */
        return DECLINED(cmd);
    
    pr_log_debug( DEBUG5, "mod_mud: mud_cmd_write" );

    if ( (dir = mud_getdir(cmd)) == NULL ){
        pr_response_add_err( R_550, "Could not resolve '%s'.", cmd->arg );
        return ERROR(cmd);
    }

    if ( !mud_verify_access(dir, MODE_WRITE) )
        return ERROR(cmd);
  
    return DECLINED(cmd);
}


MODRET mud_cmd_list( cmd_rec *cmd )
{
    char *dir = NULL;

    if ( !(mud_login & MU_AUTHENTICATED) )
        /* not our job */
        return DECLINED(cmd);
    
    pr_log_debug( DEBUG5, "mod_mud: mud_cmd_list" );

    if ( (dir = mud_getdir(cmd)) == NULL ){
        pr_response_add_err( R_550, "Could not resolve '%s'.", cmd->arg );
        return ERROR(cmd);
    }

    if ( !mud_verify_access(dir, MODE_LIST) )
        return ERROR(cmd);
  
    return DECLINED(cmd);
}

/* sendline() now has an internal buffer, to help speed up LIST output. */
static int sendline(char *fmt, ...) {
  static char listbuf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  va_list msg;
  char buf[PR_TUNABLE_BUFFER_SIZE+1] = {'\0'};
  int res = 0;

  /* A NULL fmt argument is the signal to flush the buffer */
  if (!fmt) {
    if ((res = pr_data_xfer(listbuf, strlen(listbuf))) < 0)
      pr_log_debug(DEBUG3, "pr_data_xfer returned %d, error = %s.", res,
        strerror(PR_NETIO_ERRNO(session.d->outstrm)));

    memset(listbuf, '\0', sizeof(listbuf));
    return res;
  }

  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';

  /* If buf won't fit completely into listbuf, flush listbuf */
  if (strlen(buf) >= (sizeof(listbuf) - strlen(listbuf))) {
    if ((res = pr_data_xfer(listbuf, strlen(listbuf))) < 0)
      pr_log_debug(DEBUG3, "pr_data_xfer returned %d, error = %s.", res,
        strerror(PR_NETIO_ERRNO(session.d->outstrm)));

    memset(listbuf, '\0', sizeof(listbuf));
  }

  sstrcat(listbuf, buf, sizeof(listbuf));
  return res;
}

MODRET mud_cmd_reallist( cmd_rec *cmd )
{
	char *result = NULL;
	int lines, len;
	char *dir = (cmd->argc > 1) ? cmd->argv[1] : session.cwd;

    if ( !(mud_login & MU_AUTHENTICATED) )
        /* not our job */
        return DECLINED(cmd);

	if(send_msg(&result, "LIST", session.user, dir, NULL)) {
		pr_response_add(R_550, "Error retrieving dirlist '%s'.", dir);
		return ERROR(cmd);
	}

	lines = 0;
	while(!XFER_ABORTED) {
		if (!strncasecmp(result, "OK", 2))
			break;
		if (strncasecmp("LINE", result, 4) 
			|| (result[4] != '\0' && result[4] != '\t'))
		{
			pr_log_debug(DEBUG1, "mod_mud: recvd |%s|", result);
			pr_response_add(R_550, "Error retrieving dirlist '%s'.", dir);
			break;
		}
		len = strlen(result+4);
	
  		/* If the data connection isn't open, open it now. */

		if ((session.sf_flags & SF_XFER) == 0) {
			if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
				pr_data_reset();
				return ERROR(cmd);
			}

			session.sf_flags |= SF_ASCII_OVERRIDE;
		}
		// we can use sendline(fmt, ....)
		sendline("%s", result+5);
		lines++;
		free(result);
		if (get_msg("LIST", &result, 0)) {
			pr_response_add(R_550, "Error retrieving dirlist for '%s', timeout", dir);
			break;
		}
	}	
	if (!XFER_ABORTED) {
		sendline(NULL);
	}
	free(result);

	if (XFER_ABORTED) {
		pr_data_abort(0, 0);
    	return ERROR(cmd);

	} else if (session.sf_flags & SF_XFER) {
		pr_data_close(FALSE);
	}
	return HANDLED(cmd);
}

// AUTH functions

MODRET mud_getgrgid( cmd_rec *cmd )
{
	static struct group xgroup;
	pr_log_debug( DEBUG1, "mod_mud: getgrgid() called" );
	xgroup.gr_gid = 300;
	xgroup.gr_name = "games";
	xgroup.gr_passwd = "x";
	xgroup.gr_mem = 0;
	return mod_create_data(cmd, &xgroup);
	return DECLINED(cmd);
}

MODRET mud_getgroups( cmd_rec *cmd )
{
	array_header *gids = NULL, *groups = NULL;
	if(mudgroup)
	{	
	  if(cmd->argv[1])
		{	
		  gids = (array_header *) cmd->argv[1];
		  
		  if(gids)
        *((gid_t *) push_array(gids)) = mudgroup->gr_gid;
		}
		if(cmd->argv[2])
		{	
		  groups = (array_header *) cmd->argv[2];
		  
		  if(groups)
        *((char **) push_array(groups)) = mudgroup->gr_name;
		}
  if (gids && gids->nelts > 0)
    return mod_create_data(cmd, (void *) &gids->nelts);

  else if (groups && groups->nelts > 0)
    return mod_create_data(cmd, (void *) &groups->nelts);
	}
	return DECLINED(cmd);
}

static conftable mud_config[] = {
	{ "MudUserName",  mud_set_muduser,    NULL },
	{ "MudGroupName", mud_set_mudgroup,   NULL },
    { "PathMudlib",   mud_set_pathmudlib, NULL },
    { "UDPPortno",    mud_set_udpport,    NULL },
    { NULL,           NULL,               NULL }
};


static authtable mud_auth[] = {
    { 0, "auth", pw_auth },
    { 0, "getgroups", mud_getgroups },
    { 0, "getgrgid", mud_getgrgid },
    { 0, NULL }
};


cmdtable mud_commands[] = {
    { CMD,     C_PASS,  G_NONE,  mud_cmd_pass,   FALSE, FALSE, CL_AUTH },
/* check whether the operations are allowed */
    { PRE_CMD, C_NLST,  G_DIRS,  mud_cmd_list,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_LIST,  G_DIRS,  mud_cmd_list,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_STAT,  G_DIRS,  mud_cmd_read,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_RETR,  G_READ,  mud_cmd_read,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_SIZE,  G_READ,  mud_cmd_read,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_CWD,   G_READ,  mud_cmd_list,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_XCWD,  G_READ,  mud_cmd_list,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_CDUP,  G_READ,  mud_cmd_read,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_XCUP,  G_READ,  mud_cmd_read,   TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_STOR,  G_WRITE, mud_cmd_write,  TRUE,  TRUE , CL_AUTH },
    { PRE_CMD, C_STOU,  G_WRITE, mud_cmd_write,  TRUE,  TRUE , CL_AUTH },
    { PRE_CMD, C_APPE,  G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_MKD,   G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_XMKD,  G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_RMD,   G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_XRMD,  G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_DELE,  G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_RNFR,  G_DIRS,  mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
    { PRE_CMD, C_RNTO,  G_WRITE, mud_cmd_write,  TRUE,  FALSE, CL_AUTH },
/* retrieve dir listing */
/*    { CMD,     C_LIST,  G_DIRS,  mud_cmd_reallist,TRUE, FALSE, CL_AUTH }, */
    { 0, NULL }
};


module mud_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "mud",

  /* Module configuration handler table */
  mud_config,

  /* Module command handler table */
  mud_commands,

  /* Module authentication handler table */
  mud_auth,

  /* Module initialization */
  NULL,

  /* Session initialization */
  mud_sess_init
};
