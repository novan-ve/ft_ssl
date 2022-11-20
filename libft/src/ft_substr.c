/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_substr.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/31 01:10:18 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 19:13:29 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	char	*str;
	void	*ptr;
	size_t	i;

	i = 0;
	if (s == 0)
		return (0);
	ptr = (start > len) ? malloc(1) : malloc(sizeof(char) * (len + 1));
	if (ptr == 0)
		return (0);
	str = ptr;
	if (start > len)
	{
		*str = '\0';
		return (str);
	}
	while (s[i] != '\0' && i < len)
	{
		str[i] = s[start];
		start++;
		i++;
	}
	str[len] = '\0';
	return (str);
}
