/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strjoin.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/11/01 12:15:44 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 16:33:17 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	void	*ptr;
	int		index;
	int		counter;

	index = 0;
	counter = 0;
	if (s1 == 0 || s2 == 0)
		return (0);
	ptr = malloc(sizeof(char) * (ft_strlen(s1) + ft_strlen(s2) + 1));
	if (ptr == 0)
		return (NULL);
	while (s1[index])
	{
		((char*)ptr)[index] = s1[index];
		index++;
	}
	while (s2[counter] != '\0')
	{
		((char*)ptr)[index] = s2[counter];
		index++;
		counter++;
	}
	((char*)ptr)[index] = '\0';
	return ((char*)ptr);
}
