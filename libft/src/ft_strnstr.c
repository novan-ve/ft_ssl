/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strnstr.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/28 16:49:58 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 13:30:15 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *haystack, const char *needle, size_t len)
{
	size_t	i;
	int		c;
	char	*tmp;

	i = 0;
	tmp = 0;
	if (!needle[i])
		return ((char*)haystack);
	while (haystack[i] && i < len)
	{
		if (haystack[i] == needle[0])
		{
			tmp = (char*)haystack + i;
			c = 0;
			while (haystack[i + c] == needle[c] && i + c < len)
			{
				if (!needle[c + 1])
					return (tmp);
				c++;
			}
			tmp = 0;
		}
		i++;
	}
	return (0);
}
