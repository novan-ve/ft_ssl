/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_memccpy.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/30 16:05:08 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 15:20:53 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	unsigned char			*d;
	unsigned const char		*s;

	d = dst;
	s = src;
	c = (unsigned char)c;
	while (n > 0 && *s != c)
	{
		*d = *s;
		d++;
		s++;
		n--;
	}
	if (n == 0)
		return (NULL);
	*d = *s;
	d++;
	d = (void*)d;
	return (d);
}
