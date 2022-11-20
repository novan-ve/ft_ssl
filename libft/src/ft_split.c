/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_split.c                                         :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/11/10 16:34:36 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/15 15:27:53 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static char	*ft_substr2(char const *s, unsigned int start, size_t len)
{
	char	*str;
	void	*ptr;
	size_t	i;

	i = 0;
	if (s == 0 || len <= 0)
		return (0);
	ptr = malloc(sizeof(char) * (len + 1));
	if (ptr == 0)
		return (0);
	str = ptr;
	while (s[i] != '\0' && i < len)
	{
		str[i] = s[start];
		start++;
		i++;
	}
	str[len] = '\0';
	return (str);
}

static int	ft_count(char const *s, char c)
{
	int		index;
	int		count;

	index = 0;
	count = 0;
	while (s[index] != '\0')
	{
		if (s[index] != c)
		{
			while (s[index] != '\0' && s[index] != c)
				index++;
			count++;
		}
		else
			index++;
	}
	return (count);
}

static char	**ft_free(char **s, int i)
{
	while (i >= 0)
	{
		free(s[i]);
		i--;
	}
	return (s);
}

static char	**ft_splitloop(const char *s, char **result, char c)
{
	int		i;
	int		j;
	int		start;

	i = 0;
	j = 0;
	while (s[i] != '\0' && ft_count(s, c) > 0)
	{
		if (s[i] == c)
			i++;
		else
		{
			start = i;
			while (s[i] != '\0' && s[i] != c)
				i++;
			result[j] = ft_substr2(s, start, i - start);
			if (result[j] == 0)
				return (ft_free(result, j));
			j++;
		}
	}
	result[j] = 0;
	return (result);
}

char		**ft_split(char const *s, char c)
{
	char	**result;

	result = (s == 0) ? 0 : malloc(sizeof(char *) * (ft_count(s, c) + 1));
	if (result == 0)
		return (0);
	result = ft_splitloop(s, result, c);
	return (result);
}
