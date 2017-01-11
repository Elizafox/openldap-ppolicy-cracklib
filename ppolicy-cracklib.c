/*
 * ppolicy-cracklib.c - a password policy module for OpenLDAP
 * Portions of this code inspired by python-cracklib2's VeryFascistCheck
 *
 * Copyright (C) 2017 Elizabeth Myers. All rights reserved.
 * Terms for reuse located in the LICENSE file with this source distribution.
 */

#include <syslog.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <crack.h>

#include <portable.h>
#include <slap.h>

static inline bool get_user_info(Entry *pEntry, char **gecos, char **uid)
{
	*gecos = *uid = NULL;

	for(Attribute *a = pEntry->e_attrs; a != NULL && (*gecos == NULL || *uid == NULL); a = a->a_next)
	{
		char *a_name = a->a_desc->ad_cname.bv_val;
	       	if(strcmp(a_name, "gecos") == 0 && a->a_numvals > 0)
			*gecos = a->a_vals[0].bv_val;
		else if(strcmp(a_name, "uid") == 0 && a->a_numvals > 0)
			*uid = a->a_vals[0].bv_val;
	}

	return (*uid != NULL);
}

static inline bool is_palindrome(const char *str)
{
	size_t i = 0, j = strlen(str) - 1;

	if(i == j)
		return false;

	do
	{
		if(tolower(str[i]) != tolower(str[j]))
			return false;
	} while(++i <= --j);

	return true;
}

// Check if password is sufficiently complex
static inline bool is_simple(const char *str, char **errstr)
{
	int chars[256] = {0};
	int total_digits = 0;
	int total_lower = 0;
	int total_upper = 0;
	int total_punct = 0;
	int total_space = 0;
	int total_other = 0;
	int total = 0;

	for(const char *c = str; *c != '\0'; c++, total++)
	{
		if(isdigit(*c))		total_digits++;
		else if(islower(*c))	total_lower++;
		else if(isupper(*c))	total_upper++;
		else if(ispunct(*c))	total_punct++;
		else if(isspace(*c))	total_space++;
		else		total_other++;

		(chars[(size_t)*c])++;
	}

	if(total < 8)
	{
		// Easily crackable, most likely.
		*errstr = strdup("Password is too short");
		return true;
	}

	// Convert the totals into percentages
	total_digits = (total_digits * 100) / total;
	total_lower = (total_lower * 100) / total;
	total_upper = (total_upper * 100) / total;
	total_punct = (total_punct * 100) / total;
	total_space = (total_space * 100) / total;
	total_other = (total_other * 100) / total;

	/*
	 * Require minimum and maximum percentages for specific character classes
	 * Digits (0-9):
	 *   + Small search space, so only 40% of the password (but at least 5%)
	 *
	 * Letters (A-Z, a-z):
	 *   + Larger search space, but needs to be mixed or it is feasible for cracking.
	 *   + Two classes: lower and upper
	 *   + As high as 60% is allowed, but at least 10% should be in the password for each class
	 *
	 * Punctuation (anything printable that's not a letter, digit, or space):
	 *   + Large-ish search space, 32 characters
	 *   + Uncommonly checked in password cracking (easier to go for lower-hanging fruit)
	 *   + Passwords containing it are likely to be stronger
	 *   + Allow up to 70% (more than that could weaken the password), and no less than 5% (for strength)
	 *
	 * Whitespace (tab, space):
	 *   + Only two characters, so very little benefit in mandating it
	 *   + Occasionally used in passwords, but not often
	 *   + Passwords containing more than 10% could be seriously weakened
	 *
	 * Other non-ascii characters are excluded as well due to enormous search space
	 * If more than 20%, don't bother checking, this is pretty strong as it is.
	 */

	if(total_other < 20)
	{
		// Digit checks
		if(total_digits > 40)
		{
			*errstr = strdup("Password contains too many digits");
			return true;
		}
		else if(total_digits < 5)
		{
			*errstr = strdup("Password contains too few digits");
			return true;
		}

		/// Lower checks
		if(total_lower > 60)
		{
			*errstr = strdup("Password contains too many lowercase letters");
			return true;
		}
		else if(total_lower < 10)
		{
			*errstr = strdup("Password contains too few lowercase letters");
			return true;
		}

		// Upper checks
		if(total_upper > 60)
		{
			*errstr = strdup("Password contains too many uppercase letters");
			return true;
		}
		else if(total_upper < 10)
		{
			*errstr = strdup("Password contains too few uppercase letters");
			return true;
		}

		// Punctuation checks
		if(total_punct > 70)
		{
			*errstr = strdup("Password contains too much punctuation");
			return true;
		}
		else if(total_punct < 5)
		{
			*errstr = strdup("Password contains too little punctuation");
			return true;
		}

		// Space checks
		if(total_space > 10)
		{
			*errstr = strdup("Password contains too much whitespace");
			return true;
		}
	}

	// Check for excessive number of specific characters
	int iter_total = 0;
	for(size_t i = 0; i < 255 && iter_total < total; i++)
	{
		int percent = (chars[i] * 100) / total;
		iter_total += chars[i];
		if(percent > 60)
		{
			*errstr = strdup("Password contains too many of a single character");
			return true;
		}
	}

	// The password is considered sufficiently complex
	return false;
}

int check_password (char *pPasswd, char **ppErrStr, Entry *pEntry)
{
	char *gecos = NULL, *uid = NULL;
	const char *dict = GetDefaultCracklibDict();

	openlog("slapd", LOG_PID, LOG_AUTHPRIV);

	if(pEntry != NULL)
	{
		if(!get_user_info(pEntry, &gecos, &uid))
			// Warn about this
			syslog(LOG_ERR, "Could not update password for user: couldn't find username");

		// Out of an abundance of caution
		uid = gecos = NULL;
	}

	if(is_palindrome(pPasswd))
	{
		syslog(LOG_INFO, "User %s attempted to change password to a bad password (palindrome)", uid);
		*ppErrStr = strdup("Password is a palindrome");
		closelog();
		return -1;
	}

	if(is_simple(pPasswd, ppErrStr))
	{
		syslog(LOG_INFO, "User %s attempted to change password to a bad password (insufficiently complex: %s", uid, *ppErrStr);
		closelog();
		return -1;
	}

	const char const *error = (*uid ? FascistCheckUser(pPasswd, dict, uid, gecos) : FascistCheck(pPasswd, dict));
	if(error)
	{
		syslog(LOG_INFO, "User %s attempted to change password to a bad password (cracklib: %s)", uid, error);
		*ppErrStr = strdup(error);
		closelog();
		return -1;
	}

	closelog();
	return LDAP_SUCCESS;
}
