/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strlcat.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/30 13:19:03 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/12 15:39:32 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t dstsize)
{
	size_t	index;

	index = 0;
	while (index < dstsize && dst[index] != '\0')
		index++;
	if (index != dstsize)
		ft_strlcpy(dst + index, src, dstsize - index);
	return (index + ft_strlen(src));
}
