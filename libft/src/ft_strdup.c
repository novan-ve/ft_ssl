/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strdup.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/31 00:47:33 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 16:32:03 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strdup(const char *s1)
{
	void		*ptr;
	char		*p;
	size_t		len;

	len = ft_strlen(s1) + 1;
	ptr = malloc(len);
	if (ptr == 0)
		return (NULL);
	p = ptr;
	while (len != 0)
	{
		*p = *s1;
		p++;
		s1++;
		len--;
	}
	return (ptr);
}
