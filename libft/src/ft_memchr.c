/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_memchr.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/30 23:34:42 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 15:24:16 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	const char	*str;

	str = s;
	c = (char)c;
	while (n != 0)
	{
		if (*str == c)
			return ((char*)str);
		str++;
		n--;
	}
	return (NULL);
}
