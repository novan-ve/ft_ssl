/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_memmove.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/30 16:38:49 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 16:46:10 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	char		*d;
	const char	*s;
	int			i;

	d = dst;
	s = src;
	i = 0;
	if (d == 0 && s == 0 && len != 0)
		return (0);
	if (d < s)
		while (i < (int)len)
		{
			d[i] = s[i];
			i++;
		}
	else
	{
		i = (int)len - 1;
		while (i >= 0)
		{
			d[i] = s[i];
			i--;
		}
	}
	return (dst);
}
