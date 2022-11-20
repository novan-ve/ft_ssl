/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strchr.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/29 10:23:10 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/12 15:27:15 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strchr(const char *s, int c)
{
	int		index;
	char	*s2;

	index = 0;
	s2 = (char*)s;
	while (s[index] && s[index] != c)
		index++;
	if (s[index] == c)
		return (s2 + index);
	return (NULL);
}
