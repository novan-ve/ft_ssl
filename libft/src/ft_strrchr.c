/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strrchr.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/28 15:40:51 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/12 15:45:19 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	const char	*result;

	result = 0;
	while (*s)
	{
		if (*s == (char)c)
			result = s;
		s++;
	}
	if (!(char)c)
		return ((char*)s);
	return ((char*)result);
}
